import azure.functions as func
import json
import logging
import os
from datetime import datetime

# Make sure these are in requirements.txt
from google import genai
from google.genai import types
from azure.data.tables import TableClient, UpdateMode
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

# --- CONFIGURATION ---
RATE_LIMIT_TABLE = "RateLimits"
DAILY_GLOBAL_LIMIT = 50
DAILY_IP_LIMIT = 5

# --- GLOBAL CLIENT INITIALIZATION (Best Practice) ---
# DO NOT initialize at module level - it can crash import and hide all functions!
# Use lazy initialization inside the function instead.
_table_client_cache = None

def get_table_client():
    global _table_client_cache
    if _table_client_cache is not None:
        return _table_client_cache
    
    try:
        table_service_uri = os.environ.get("AzureWebJobsStorage__tableServiceUri")
        connection_string = os.environ.get("AzureWebJobsStorage")
        
        if table_service_uri:
            # Managed Identity (Production/Cloud)
            credential = DefaultAzureCredential()
            _table_client_cache = TableClient(endpoint=table_service_uri, credential=credential, table_name=RATE_LIMIT_TABLE)
        elif connection_string:
            # Connection String (Local Dev)
            _table_client_cache = TableClient.from_connection_string(conn_str=connection_string, table_name=RATE_LIMIT_TABLE)
        return _table_client_cache
    except Exception as e:
        logging.error(f"Failed to initialize Table Client: {e}")
        return None

def check_rate_limit(ip_address):
    """Enforces rate limits using lazy-initialized TableClient."""
    table_client = get_table_client()
    if not table_client:
        return True # Fail open if storage is misconfigured

    try:
        # Create table if not exists (only tries once ideally, but safe here)
        # Note: In high-scale prod, move this to a deployment script, not runtime code.
        try:
            table_client.create_table()
        except Exception:
            pass

        today = datetime.now().strftime("%Y-%m-%d")
        
        # 1. Global Check
        try:
            global_entity = table_client.get_entity(partition_key=today, row_key="GLOBAL")
            global_count = global_entity["Count"] + 1
            if global_count > DAILY_GLOBAL_LIMIT:
                logging.warning(f"Global rate limit exceeded: {global_count}")
                return False
            global_entity["Count"] = global_count
            table_client.update_entity(mode=UpdateMode.REPLACE, entity=global_entity)
        except ResourceNotFoundError:
            table_client.create_entity(entity={"PartitionKey": today, "RowKey": "GLOBAL", "Count": 1})

        # 2. IP Check
        sanitized_ip = ip_address.replace(":", "_")
        try:
            ip_entity = table_client.get_entity(partition_key=today, row_key=sanitized_ip)
            ip_count = ip_entity["Count"] + 1
            if ip_count > DAILY_IP_LIMIT:
                logging.warning(f"IP rate limit exceeded for {ip_address}: {ip_count}")
                return False
            ip_entity["Count"] = ip_count
            table_client.update_entity(mode=UpdateMode.REPLACE, entity=ip_entity)
        except ResourceNotFoundError:
            table_client.create_entity(entity={"PartitionKey": today, "RowKey": sanitized_ip, "Count": 1})

        return True

    except Exception as e:
        logging.error(f"Rate limit check failed: {e}")
        return True

@app.route(route="compare", methods=["POST", "OPTIONS"], auth_level=func.AuthLevel.ANONYMOUS)
def compare_attacks(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Compare attacks function triggered")

    # CORS Headers
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json"
    }

    if req.method == "OPTIONS":
        return func.HttpResponse(status_code=204, headers=headers)

    # ... (Rest of your IP check logic remains the same) ...
    # IP Extraction
    ip = req.headers.get("x-forwarded-for")
    if not ip:
        ip = "unknown_ip"
    if "," in ip:
        ip = ip.split(",")[0].strip()

    if not check_rate_limit(ip):
        return func.HttpResponse(
            json.dumps({"error": "Rate limit exceeded."}),
            status_code=429,
            headers=headers
        )

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(json.dumps({"error": "Invalid JSON"}), status_code=400, headers=headers)

    date1 = req_body.get("date1")
    date2 = req_body.get("date2")
    data1 = req_body.get("data1", [])
    data2 = req_body.get("data2", [])

    if not date1 or not date2:
        return func.HttpResponse(json.dumps({"error": "Dates required"}), status_code=400, headers=headers)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return func.HttpResponse(json.dumps({"error": "Server Config Error"}), status_code=500, headers=headers)

    # Quick Stats
    def get_stats(data):
        # Use .get with 0 default to prevent KeyErrors
        total = sum(int(item.get('attack_count', item.get('FailureCount', 0))) for item in data)
        return total, len(data)

    t1, i1 = get_stats(data1)
    t2, i2 = get_stats(data2)

    # Build comprehensive prompt with actual data samples
    prompt = f"""You are a cybersecurity analyst reviewing RDP honeypot attack data.

Compare attacks between two dates and provide insights.

**Date 1: {date1}**
- Total Attack Events: {t1}
- Unique Attacking IPs: {i1}
- Top 20 Attackers (IP, Country, Attack Count):
{json.dumps(data1[:20], indent=2)}

**Date 2: {date2}**
- Total Attack Events: {t2}
- Unique Attacking IPs: {i2}
- Top 20 Attackers (IP, Country, Attack Count):
{json.dumps(data2[:20], indent=2)}

Analyze this data and respond with a JSON object containing these STRING fields (not nested objects):
{{
    "summary": "One sentence overview of the trend between the two dates.",
    "attack_volume": "Analysis of count changes - was it higher or lower? By how much?",
    "geographic_shifts": "Which countries appeared or disappeared between dates? Any new attack sources?",
    "notable_ips": "Any IPs with unusually high attack counts worth blocking?",
    "target_behavior": "Any patterns in the targeting behavior?"
}}

IMPORTANT: All values must be plain text strings, not nested objects."""

    try:
        client = genai.Client(api_key=api_key)
        
        # New SDK Syntax
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt, # You can pass string directly in new SDK
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        
        # Clean response if needed (API usually handles JSON mode well now)
        cleaned_text = response.text.replace("```json", "").replace("```", "").strip()
        
        return func.HttpResponse(cleaned_text, status_code=200, headers=headers)

    except Exception as e:
        logging.error(f"AI Error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, headers=headers)