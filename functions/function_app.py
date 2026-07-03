import azure.functions as func
import json
import logging
import os
import re
from datetime import datetime, timezone

from google import genai
from google.genai import types
from azure.data.tables import TableClient, UpdateMode
from azure.core import MatchConditions
from azure.core.exceptions import (
    ResourceNotFoundError,
    ResourceExistsError,
    HttpResponseError,
)
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

# --- CONFIGURATION ---
RATE_LIMIT_TABLE = "RateLimits"
DAILY_GLOBAL_LIMIT = 50
DAILY_IP_LIMIT = 5
MAX_INCREMENT_RETRIES = 5
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_TIMEOUT_MS = 30_000
TOP_N_ATTACKERS = 20

# Restrict CORS to the site origin (override via app setting if a custom domain is added).
ALLOWED_ORIGIN = os.environ.get(
    "ALLOWED_ORIGIN", "https://orange-wave-0061ed81e.6.azurestaticapps.net"
)
# The rate limiter guards a *paid* Gemini quota, so it fails CLOSED by default:
# if the counter store is unavailable we deny rather than let unbounded traffic
# through. Set RATE_LIMIT_FAIL_OPEN=true to prefer availability over the spend cap.
FAIL_OPEN = os.environ.get("RATE_LIMIT_FAIL_OPEN", "false").lower() == "true"

# --- LAZY CLIENT INITIALIZATION ---
# Do NOT initialize clients at module level — a failure there crashes import
# and hides every function. Initialize on first use and cache instead.
_table_client_cache = None
_genai_client_cache = None
_table_ensured = False


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
            _table_client_cache = TableClient(
                endpoint=table_service_uri,
                credential=credential,
                table_name=RATE_LIMIT_TABLE,
            )
        elif connection_string:
            # Connection String (Local Dev)
            _table_client_cache = TableClient.from_connection_string(
                conn_str=connection_string, table_name=RATE_LIMIT_TABLE
            )
        return _table_client_cache
    except Exception:
        logging.exception("Failed to initialize Table Client")
        return None


def get_genai_client(api_key: str):
    """Cache the Gemini client and bound every call with a timeout."""
    global _genai_client_cache
    if _genai_client_cache is None:
        try:
            _genai_client_cache = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
            )
        except (TypeError, AttributeError):
            # Older SDK without http_options support — fall back gracefully.
            _genai_client_cache = genai.Client(api_key=api_key)
    return _genai_client_cache


def _row_key(ip_address: str) -> str:
    """Strip characters Azure Table Storage disallows in keys."""
    return re.sub(r"[\\/#?\x00-\x1f\x7f-\x9f]", "_", ip_address)


def _ensure_table(table_client) -> None:
    global _table_ensured
    if _table_ensured:
        return
    try:
        table_client.create_table()
    except ResourceExistsError:
        pass
    _table_ensured = True


def _check_and_increment(table_client, partition: str, row_key: str, limit: int) -> bool:
    """
    Atomically increment a daily counter and return whether the request is allowed.

    Uses optimistic concurrency (ETag / If-Match): the previous code did a plain
    read-modify-write, so concurrent invocations could both read N and both write
    N+1, silently losing increments and letting the limit be exceeded. Here a lost
    race raises HTTP 412 and we retry against fresh state.
    """
    for _ in range(MAX_INCREMENT_RETRIES):
        try:
            entity = table_client.get_entity(partition_key=partition, row_key=row_key)
        except ResourceNotFoundError:
            try:
                table_client.create_entity(
                    entity={"PartitionKey": partition, "RowKey": row_key, "Count": 1}
                )
                return True  # first request in this window
            except ResourceExistsError:
                continue  # created concurrently — loop and take the update path
        else:
            new_count = int(entity["Count"]) + 1
            if new_count > limit:
                return False
            entity["Count"] = new_count
            try:
                table_client.update_entity(
                    entity=entity,
                    mode=UpdateMode.REPLACE,
                    etag=entity.metadata["etag"],
                    match_condition=MatchConditions.IfNotModified,
                )
                return True
            except HttpResponseError as e:
                if e.status_code == 412:
                    continue  # lost the race; re-read and retry
                raise
    # Ran out of retries under heavy contention — deny to protect the spend cap.
    logging.warning("Rate limit increment exhausted retries for %s/%s", partition, row_key)
    return False


def check_rate_limit(ip_address: str) -> bool:
    """Enforce global and per-IP daily limits with atomic counters."""
    table_client = get_table_client()
    if not table_client:
        logging.error("Rate limit storage unavailable (fail_open=%s)", FAIL_OPEN)
        return FAIL_OPEN

    try:
        _ensure_table(table_client)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if not _check_and_increment(table_client, today, "GLOBAL", DAILY_GLOBAL_LIMIT):
            logging.warning("Global daily rate limit reached")
            return False
        if not _check_and_increment(table_client, today, _row_key(ip_address), DAILY_IP_LIMIT):
            logging.warning("Per-IP daily rate limit reached for %s", ip_address)
            return False
        return True
    except Exception:
        logging.exception("Rate limit check failed")
        return FAIL_OPEN


def _cors_headers() -> dict:
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json",
        "Vary": "Origin",
    }


def _error(message: str, status_code: int, headers: dict) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"error": message}), status_code=status_code, headers=headers
    )


@app.route(route="compare", methods=["POST", "OPTIONS"], auth_level=func.AuthLevel.ANONYMOUS)
def compare_attacks(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Compare attacks function triggered")
    headers = _cors_headers()

    if req.method == "OPTIONS":
        return func.HttpResponse(status_code=204, headers=headers)

    # IP extraction (first hop in x-forwarded-for)
    ip = req.headers.get("x-forwarded-for") or "unknown_ip"
    if "," in ip:
        ip = ip.split(",")[0].strip()

    if not check_rate_limit(ip):
        return _error("Rate limit exceeded.", 429, headers)

    try:
        req_body = req.get_json()
    except ValueError:
        return _error("Invalid JSON", 400, headers)

    date1 = req_body.get("date1")
    date2 = req_body.get("date2")
    data1 = req_body.get("data1", [])
    data2 = req_body.get("data2", [])

    if not date1 or not date2:
        return _error("Dates required", 400, headers)
    if not isinstance(data1, list) or not isinstance(data2, list):
        return _error("data1 and data2 must be arrays", 400, headers)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logging.error("GEMINI_API_KEY not configured")
        return _error("Server configuration error", 500, headers)

    def get_stats(data):
        total = 0
        for item in data:
            if isinstance(item, dict):
                total += int(item.get("attack_count", item.get("FailureCount", 0)) or 0)
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
{json.dumps(data1[:TOP_N_ATTACKERS], indent=2)}

**Date 2: {date2}**
- Total Attack Events: {t2}
- Unique Attacking IPs: {i2}
- Top 20 Attackers (IP, Country, Attack Count):
{json.dumps(data2[:TOP_N_ATTACKERS], indent=2)}

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
        client = get_genai_client(api_key)
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )

        text = response.text
        if not text:
            logging.error("Gemini returned an empty response")
            return _error("Analysis returned no content", 502, headers)

        # JSON mode normally returns clean JSON; strip stray code fences defensively.
        cleaned_text = text.replace("```json", "").replace("```", "").strip()
        return func.HttpResponse(cleaned_text, status_code=200, headers=headers)

    except Exception:
        # Log the full detail server-side; never leak internals to anonymous callers.
        logging.exception("Gemini call failed")
        return _error("Upstream analysis failed", 502, headers)
