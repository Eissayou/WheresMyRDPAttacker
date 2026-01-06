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
