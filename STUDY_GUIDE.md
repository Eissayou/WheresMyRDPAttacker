# Comprehensive Azure Honeypot Study Guide

> **Objective:** Master the architecture, code, and infrastructure of your RDP Threat Map project to explain it confidently in an interview.

---

## 1. The "Elevator Pitch"
"I built a cloud-native honeypot that visualizes RDP brute-force attacks in real-time. It uses an intentionally vulnerable Windows VM to attract attackers, collects logs via the Azure Monitor Agent, processes them with a serverless Logic App pipeline, and visualizes the data on an interactive map. I also added an AI feature using Azure Functions and Gemini to analyze attack trends between different dates."

---

## 2. Architecture & Data Flow

### The Pipeline (Step-by-Step)
1.  **The Bait:** A Windows Server 2022 VM (`HoneyVM`) with the Firewall disabled and Port 3389 (RDP) open to the world.
2.  **The Trigger:** An attacker tries to log in. Windows logs **Event ID 4625** (An account failed to log on).
3.  **Collection:** The **Azure Monitor Agent (AMA)** reads this event and pushes it to your **Log Analytics Workspace**.
4.  **Processing (ETL):**
    *   A **Logic App** (`DataParser`) wakes up every 30 minutes.
    *   It runs a **KQL Query** to aggregate attacks by IP and geolocation.
    *   It saves the result as a static JSON file (`attacks_YYYY-MM-DD.json`) to a public **Blob Storage** container.
5.  **Visualization:**
    *   The frontend (Static Web App) fetches this JSON file directly from Blob Storage.
    *   It renders the attacks using **Leaflet.js**.

### The AI Feature (On-Demand)
*   **User Action:** User selects two dates to compare.
*   **Frontend:** Calls your Python **Azure Function** (`/api/compare`).
*   **Backend:**
    1.  Checks Rate Limits (Table Storage).
    2.  Constructs a prompt with attack stats from both dates.
    3.  Calls Google **Gemini API**.
    4.  Returns a text summary of the trends.

---

## 3. Key Technical Challenges ("War Stories")
*Interviewers love hearing about what went wrong. Use these real examples from your troubleshooting:*

### A. The "It works on my machine" Deployment Issue
*   **Problem:** You deployed the Python Function from your Mac, but it failed in Azure with "0 functions found".
*   **Root Cause:** The deployment uploaded macOS-specific binaries (wheels) which are incompatible with Azure's Linux environment.
*   **Fix:** You learned to use `--build remote` during deployment (`func azure functionapp publish ... --build remote`), forcing Azure to build the dependencies on the Linux server side.

### B. The Dependency Injection Crash
*   **Problem:** The Function App would crash immediately upon startup.
*   **Root Cause:** You were initializing the `TableClient` (for rate limiting) at the *global scope* of the file. If the Managed Identity wasn't ready instantly, the script would fail to import.
*   **Fix:** You implemented **Lazy Initialization**. You moved the client setup inside a `get_table_client()` function so it only connects when a request actually comes in.

### C. Logic App vs. Traditional Code
*   **Decision:** Why use a Logic App instead of a Python script for the ETL?
*   **Answer:** It's serverless and visual. You don't need to maintain a 24/7 server just to run a query every 30 minutes. It handles the "Auth" to Log Analytics and Blob Storage natively with Managed Identities, avoiding complex token management code.

---

## 4. Code Deep Dive

### Frontend (`index.html` & JS)
*   **Efficiency:** The map does **not** query the database. It fetches a static JSON file. This makes it incredibly fast and cheap (Penny scale).
*   **Polling:** You implemented a "Time to Next Refresh" countdown that syncs with the Logic App's 30-minute schedule.
*   **Clustering:** Used `Leaflet.markercluster` to group thousands of attack points so the browser doesn't crash.

### Backend (`function_app.py`)
*   **Rate Limiting Algorithm:**
    *   You didn't use Redis (too expensive). You used **Azure Table Storage**.
    *   **Logic:**
        1.  Create a composite key: `PartitionKey=Date`, `RowKey=IP_Address`.
        2.  Increment a counter entity.
        3.  If `Count > 5` (per IP) or `Global > 50`, reject the request (`429 Too Many Requests`).
*   **Gemini Integration:**
    *   Uses `google-genai` SDK.
    *   Model: `gemini-2.5-flash`.
    *   Prompt Engineering: You specifically ask for JSON output (or structured text) to ensure the frontend can display it strictly.

---

## 5. Infrastructure as Code (Terraform)
*You retroactively created this to banish "ClickOps".*

### Project Structure
*   `main.tf`: The Resource Group foundation.
*   `network.tf`: The VNet, Public IP, and the "Open" NSG (Allow 3389).
*   `vm.tf`:
    *   **CustomScriptExtension:** Disables Windows Firewall via PowerShell (`Set-NetFirewallProfile ... -Enabled False`).
    *   **Data Collection Rule (DCR):** The modern way to filter logs (ONLY send Security Events) to save money.
*   `logic_app.tf`:
    *   Defines the Workflow JSON inline.
    *   **Gotcha:** The API Connections (to Log Analytics) usually require manual authorization in the Portal after deployment.

### Terraform Commands to Know
*   `terraform init`: Downloads the Azure providers.
*   `terraform plan`: "Dry run" to see what will happen.
*   `terraform apply`: Executes the changes.
*   `terraform.tfvars`: Where your secrets (like `vm_password`) live. **Never commit this file.**

---

## 6. Security & Best Practices
*   **Managed Identities:** Your resources talk to each other (Logic App -> Blob, Function -> Table) using their Azure Identity, not connection strings. This is a huge security win.
*   **Least Privilege:** The Logic App only has "Storage Blob Data Contributor" on the storage account, not "Owner".
*   **Cost Control:**
    *   Logic App: Consumption Plan (Pay per run).
    *   Function App: Consumption Plan (Y1).
    *   No expensive Gateways or Load Balancers.

---

## 7. Sample Interview Questions

**Q: Why Azure?**
**A:** (Sample) "I wanted to gain experience with Microsoft's ecosystem, particularly how well their security tools (Sentinel/Log Analytics) integrate with Windows Server events."

**Q: How would you scale this to handle 1 million attacks?**
**A:**
1.  **Map:** Stop fetching one giant JSON. Use vector tiles or a backend that returns only the points in the viewport (BBOX query).
2.  **Ingestion:** The Analysis Pipeline might need an Event Hub instead of raw Log Analytics polling if the data volume gets massive.

**Q: What would you do differently next time?**
**A:** "I'd automate the Logic App API Connection authorization. Currently, it's a manual step, which breaks the theoretical 'one-click deploy' promise of Terraform."
