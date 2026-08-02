# Azure Functions Deployment Troubleshooting Guide

This document covers issues encountered deploying a Python V2 Azure Function from a Mac (Apple Silicon) and their solutions.

---

## 🔴 Issue 1: "Functions in AIAnalysis:" Shows Empty (0 Functions)

**Symptom:**
```
Deployment completed successfully.
[...] Syncing triggers...
Functions in AIAnalysis:
```
No functions listed despite successful upload.

**Root Cause:**
Using `--build local` on Mac downloads **macOS ARM64 wheels** which are **incompatible with Azure's Linux x86 container**.

**Solution:**
Use remote build instead:
```bash
# ❌ DON'T use this on Mac:
func azure functionapp publish <app-name> --build local

# ✅ USE this instead:
func azure functionapp publish <app-name> --build remote
```

Remote build sends your source code to Azure and builds packages directly on the Linux environment.

---

## 🔴 Issue 2: AzureWebJobsStorage Connection String Error

**Symptom:**
```
Error creating a Blob container reference. Please make sure your connection string in "AzureWebJobsStorage" is valid
```

**Root Cause:**
`local.settings.json` had `"AzureWebJobsStorage": "UseDevelopmentStorage=true"` which only works with local Azurite emulator.

**Solution:**
1. Go to Azure Portal → Storage Accounts → Your storage account
2. Under **Security + networking** → **Access keys**
3. Copy the **Connection string**
4. Add it to Azure Portal → Function App → **Environment variables**:
   - Name: `AzureWebJobsStorage`
   - Value: `DefaultEndpointsProtocol=https;AccountName=...`

---

## 🔴 Issue 3: Python V2 Functions Not Discovered

**Symptom:**
Logs show:
```
Reading functions metadata (Custom)
0 functions found (Custom)
```

**Root Cause:**
Missing feature flag for Python V2 worker indexing.

**Solution:**
Add this app setting in Azure Portal:
- Name: `AzureWebJobsFeatureFlags`
- Value: `EnableWorkerIndexing`

---

## 🔴 Issue 4: ModuleNotFoundError at Runtime

**Symptom:**
```
ModuleNotFoundError: No module named 'azure.data'
```

**Root Cause:**
Dependencies weren't installed correctly in deployment package.

**Solution:**
1. Clear stale packages: `rm -rf .python_packages`
2. Reinstall locally: `pip install -r requirements.txt`
3. Deploy with remote build: `func azure functionapp publish <app-name> --build remote`

---

## 🔴 Issue 5: Module-Level Code Crashes Import

**Symptom:**
Functions work locally but show 0 functions in Azure.

**Root Cause:**
Code like this runs at import time:
```python
# BAD - runs during import, can crash before functions are registered
client = TableClient(...)
```

If `DefaultAzureCredential()` fails before the managed identity context is ready, the entire module fails to import.

**Solution:**
Use lazy initialization:
```python
# GOOD - only runs when the function is actually called
_client_cache = None

def get_client():
    global _client_cache
    if _client_cache is None:
        _client_cache = TableClient(...)
    return _client_cache
```

---

## 🔴 Issue 6: AI Panel Shows "Could not reach the analysis service"

**Symptom:**
The map and leaderboards load fine, but clicking **Analyze** fails immediately:
```
Analysis Failed
Could not reach the analysis service from http://localhost:8081.
This is usually the origin missing from the Function's ALLOWED_ORIGIN setting,
or the service being offline.
```
In DevTools the request never appears in the Network tab, and the console shows
`TypeError: Failed to fetch`.

**Root Cause:**
CORS, not a Function crash. When the page's origin isn't allowlisted the browser
rejects the preflight and cancels the request before it is ever sent — which is
why nothing reaches the server and the error is so unhelpful.

> ⚠️ **There are TWO CORS layers, and the platform one wins.**
>
> 1. **Azure platform CORS** on the Function App (`az functionapp cors`). This
>    answers the `OPTIONS` preflight *before your Python runs* and injects
>    `Access-Control-Allow-Origin` on responses.
> 2. **`ALLOWED_ORIGIN` in `function_app.py`**, which sets the same header from
>    application code.
>
> An origin in the platform list is accepted **even if it is absent from
> `ALLOWED_ORIGIN`**. So editing the code alone will not lock anything down.
> Always check both:
>
> ```bash
> az functionapp cors show -g HONEYY -n AIAnalysis --query allowedOrigins -o tsv
> ```
>
> A telltale sign the platform layer is handling preflight: the `OPTIONS`
> response lacks `Access-Control-Max-Age` while the actual `POST` response has
> it — the header is set by the code, which preflight never reaches.

Origins must match **exactly**, including scheme and port:
`http://localhost:8081` and `http://localhost:8080` are different origins, and
so are `https://eissayou.com` and `https://www.eissayou.com`.

The map and leaderboards are unaffected because they read public blobs, which
have no CORS restriction.

**Confirm it's CORS** (this costs nothing — no Gemini call):
```bash
curl -s -i -X OPTIONS \
  https://<your-function>.azurewebsites.net/api/compare \
  -H "Origin: http://localhost:8081" \
  -H "Access-Control-Request-Method: POST"
```
If the response has no `Access-Control-Allow-Origin` matching your origin, that's
the problem. A `204` with a matching header means CORS is fine and the issue is
elsewhere.

**Solution:**
For a **custom domain**, add it permanently to the `ALLOWED_ORIGIN` app setting
(comma-separated) and restart the Function App:

| Setting | Value |
|---------|-------|
| `ALLOWED_ORIGIN` | `https://honeypot.eissayou.com,https://orange-wave-0061ed81e.6.azurestaticapps.net` |

For **local development**, add your origin the same way but treat it as
temporary, and remove it when you're finished:

```bash
# enable local access
az functionapp config appsettings set \
  --name AIAnalysis --resource-group <your-rg> \
  --settings "ALLOWED_ORIGIN=https://honeypot.eissayou.com,https://orange-wave-0061ed81e.6.azurestaticapps.net,http://localhost:8081"

# revert to production-only when done
az functionapp config appsettings set \
  --name AIAnalysis --resource-group <your-rg> \
  --settings "ALLOWED_ORIGIN=https://honeypot.eissayou.com,https://orange-wave-0061ed81e.6.azurestaticapps.net"
```

And for the platform layer:

```bash
# add (temporarily) / remove a dev origin
az functionapp cors add    -g HONEYY -n AIAnalysis --allowed-origins "http://127.0.0.1:5500"
az functionapp cors remove -g HONEYY -n AIAnalysis --allowed-origins "http://127.0.0.1:5500"
```

> ⚠️ Don't leave a `localhost` / `127.0.0.1` origin allowlisted in either layer.
> `Origin` is set by the browser, so allowing `http://127.0.0.1:5500` lets
> **anyone** serving a page on that port call this endpoint and spend your Gemini
> quota. The per-IP (5/day) and global (50/day) rate limits cap the damage but
> don't prevent it. Current production allowlist is deliberately just
> `https://portal.azure.com` (for the portal's Code+Test console), the custom
> domain `https://honeypot.eissayou.com`, and the legacy Static Web App origin.

---

## ✅ Complete Working Deployment Command

```bash
cd functions
func azure functionapp publish <your-app-name> --build remote
```

---

## 📋 Required Azure App Settings

| Setting | Value |
|---------|-------|
| `FUNCTIONS_WORKER_RUNTIME` | `python` |
| `FUNCTIONS_EXTENSION_VERSION` | `~4` |
| `AzureWebJobsFeatureFlags` | `EnableWorkerIndexing` |
| `AzureWebJobsStorage` | `DefaultEndpointsProtocol=https;...` |
| `GEMINI_API_KEY` | Your API key |
| `ALLOWED_ORIGIN` | Comma-separated CORS allowlist. Optional — defaults to the Static Web App origin only. See Issue 6. |
| `RATE_LIMIT_FAIL_OPEN` | Optional. `false` (default) denies requests when the counter store is unavailable, protecting the paid Gemini quota. |
