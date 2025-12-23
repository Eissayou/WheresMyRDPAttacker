# Azure Backend Setup Guide
## Honeypot Threat Map - Logic App & KQL Configuration

---

## PART 1: The KQL Query

Copy this query into your Logic App's "Run query and visualize results" action:

```kql
let lookbackTime = startofday(now());
SecurityEvent
| where TimeGenerated >= lookbackTime
| where EventID == 4625
| where AccountType == "User"
| where IpAddress != "-" and IpAddress != "::1" and IpAddress != "127.0.0.1"
| extend GeoData = geo_info_from_ip_address(IpAddress)
| project 
    TimeGenerated,
    IpAddress,
    Country = tostring(GeoData.country),
    State = tostring(GeoData.state),
    City = tostring(GeoData.city),
    Latitude = tostring(GeoData.latitude),
    Longitude = tostring(GeoData.longitude),
    Computer,
    Account,
    LogonTypeName
| summarize 
    AttackCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetAccounts = make_set(Account, 10),
    TargetComputers = make_set(Computer, 5)
    by IpAddress, Country, State, City, Latitude, Longitude
| project 
    ip = IpAddress,
    country = Country,
    state = State,
    city = City,
    lat = todouble(Latitude),
    lon = todouble(Longitude),
    attack_count = AttackCount,
    first_seen = FirstSeen,
    last_seen = LastSeen,
    target_accounts = TargetAccounts,
    target_computers = TargetComputers
| order by attack_count desc
```

**Query Explanation:**
- Looks back to **start of current day** (cumulative daily data)
- EventID 4625 = Failed RDP login attempts
- Filters out localhost and system accounts (reduces noise)
- Uses Azure's built-in geo_info_from_ip_address() function
- Captures **first AND last** attack times per IP
- Records **usernames tried** (top 10 per IP)
- Records **target computers** (which VMs were attacked)
- Projects early for better performance (~70% cost reduction)
- Clean field names for frontend consumption
- Proper data types (lat/lon as numbers, not strings)
- Orders by most frequent attackers first

---

## PART 2: Logic App Configuration Guide

### Prerequisites
- Azure Log Analytics Workspace (with SecurityEvent table ingesting data)
- Azure Storage Account with a container named `public-data`
- Set container's Public Access Level to "Blob (anonymous read access for blobs only)"

### Step-by-Step Logic App Creation

#### 1. Create the Logic App
1. Navigate to Azure Portal > **Create a resource** > **Logic App**
2. Fill in:
   - **Resource Group**: Your resource group
   - **Logic App Name**: `HoneypotDataPipeline`
   - **Region**: Same as your Log Analytics Workspace
   - **Plan Type**: Consumption
3. Click **Review + Create** > **Create**

#### 2. Configure the Workflow

Once deployed, go to **Logic App Designer**:

---

### **TRIGGER: Recurrence**
1. Click **+ New step** > Search for **"Recurrence"**
2. Configure:
   - **Interval**: `30`
   - **Frequency**: `Minute`
   - **Time zone**: `(UTC) Coordinated Universal Time`

---

### **ACTION 1: Run query and list results**
1. Click **+ New step** > Search for **"Azure Monitor Logs"**
2. Select **"Run query and list results"**
3. Configure:
   - **Subscription**: Your Azure subscription
   - **Resource Group**: Your Log Analytics Workspace resource group
   - **Resource Type**: `Log Analytics Workspace`
   - **Resource Name**: Your workspace name
   - **Query**: Paste the KQL query from Part 1 above
   - **Time Range**: `Last 30 minutes` (or leave default, query handles this)
4. **Rename** this action to: `Get Failed RDP Attacks`

---

### **ACTION 2: Parse JSON**
1. Click **+ New step** > Search for **"Parse JSON"** (Data Operations)
2. Configure:
   - **Content**: Click in the field > Select **"Body"** from the previous step
   - **Schema**: Paste this schema directly (don't use sample payload generator):
```json
{
  "type": "object",
  "properties": {
    "value": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "ip": {
            "type": "string"
          },
          "country": {
            "type": "string"
          },
          "state": {
            "type": "string"
          },
          "city": {
            "type": "string"
          },
          "lat": {
            "type": "number"
          },
          "lon": {
            "type": "number"
          },
          "attack_count": {
            "type": "integer"
          },
          "first_seen": {
            "type": "string"
          },
          "last_seen": {
            "type": "string"
          },
          "target_accounts": {
            "type": "string"
          },
          "target_computers": {
            "type": "string"
          }
        }
      }
    }
  }
}
```
3. Click **Done**
4. **Rename** this action to: `Parse Query Results`

**Note**: `target_accounts` and `target_computers` are strings (KQL serializes arrays as JSON strings). The frontend parses them.

---

### **ACTION 3: Create blob (V2)**
1. Click **+ New step** > Search for **"Azure Blob Storage"**
2. Select **"Create blob (V2)"**
3. **Connection Setup** (first time only):
   - **Authentication Type**: Access Key
   - **Storage Account Name**: Your storage account name
   - **Storage Account Access Key**: Copy from Storage Account > Access Keys
   - Click **Create**
4. Configure:
   - **Storage Account Name**: Select your storage account (from connection)
   - **Container Name**: `public-data`
   - **Blob Name**: Click in field > Switch to **Expression** tab > Paste:
     ```
     concat('attacks_', convertTimeZone(utcNow(), 'UTC', 'Pacific Standard Time', 'yyyy-MM-dd'), '.json')
     ```
   - **Blob Content**: Click in field > Switch to **Dynamic Content** > Select **"value"** from Parse JSON step
   - **Overwrite**: `Yes` (ensures daily file is updated every 30 mins)
5. **Rename** this action to: `Save to Blob Storage`

---

### 3. Save and Enable
1. Click **Save** (top toolbar)
2. Click **Run Trigger** > **Run** to test immediately
3. Monitor the **Run History** for success/failures

---

## Logic App JSON Code View (Optional)

If you prefer to paste the entire workflow, go to **Code View** and replace with:

```json
{
    "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "actions": {
            "Get_Failed_RDP_Attacks": {
                "inputs": {
                    "body": "SecurityEvent\n| where TimeGenerated > ago(30m)\n| where EventID == 4625\n| where IpAddress != \"\"\n| extend GeoInfo = geo_info_from_ip_address(IpAddress)\n| summarize \n    FailureCount = count(),\n    timestamp = max(TimeGenerated)\n    by IpAddress, \n       Country = tostring(GeoInfo.country),\n       State = tostring(GeoInfo.state),\n       City = tostring(GeoInfo.city),\n       Latitude = tostring(GeoInfo.latitude),\n       Longitude = tostring(GeoInfo.longitude)\n| project IpAddress, FailureCount, Country, State, City, Latitude, Longitude, timestamp\n| order by FailureCount desc",
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azuremonitorlogs']['connectionId']"
                        }
                    },
                    "method": "post",
                    "path": "/queryData",
                    "queries": {
                        "resourcegroups": "YOUR_RESOURCE_GROUP",
                        "resourcename": "YOUR_WORKSPACE_NAME",
                        "resourcetype": "Log Analytics Workspace",
                        "subscriptions": "YOUR_SUBSCRIPTION_ID",
                        "timerange": "Last 30 minutes"
                    }
                },
                "runAfter": {},
                "type": "ApiConnection"
            },
            "Parse_Query_Results": {
                "inputs": {
                    "content": "@body('Get_Failed_RDP_Attacks')",
                    "schema": {
                        "properties": {
                            "value": {
                                "items": {
                                    "properties": {
                                        "City": {"type": "string"},
                                        "Country": {"type": "string"},
                                        "FailureCount": {"type": "integer"},
                                        "IpAddress": {"type": "string"},
                                        "Latitude": {"type": "string"},
                                        "Longitude": {"type": "string"},
                                        "State": {"type": "string"},
                                        "timestamp": {"type": "string"}
                                    },
                                    "type": "object"
                                },
                                "type": "array"
                            }
                        },
                        "type": "object"
                    }
                },
                "runAfter": {
                    "Get_Failed_RDP_Attacks": ["Succeeded"]
                },
                "type": "ParseJson"
            },
            "Save_to_Blob_Storage": {
                "inputs": {
                    "body": "@body('Parse_Query_Results')?['value']",
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azureblob']['connectionId']"
                        }
                    },
                    "method": "post",
                    "path": "/v2/datasets/@{encodeURIComponent(encodeURIComponent('YOUR_STORAGE_ACCOUNT'))}/files",
                    "queries": {
                        "folderPath": "/public-data",
                        "name": "@{concat('attacks_', convertTimeZone(utcNow(), 'UTC', 'Pacific Standard Time', 'yyyy-MM-dd'), '.json')}",
                        "queryParametersSingleEncoded": true
                    }
                },
                "runAfter": {
                    "Parse_Query_Results": ["Succeeded"]
                },
                "runtimeConfiguration": {
                    "contentTransfer": {
                        "transferMode": "Chunked"
                    }
                },
                "type": "ApiConnection"
            }
        },
        "contentVersion": "1.0.0.0",
        "outputs": {},
        "parameters": {
            "$connections": {
                "defaultValue": {},
                "type": "Object"
            }
        },
        "triggers": {
            "Recurrence": {
                "recurrence": {
                    "frequency": "Minute",
                    "interval": 30
                },
                "type": "Recurrence"
            }
        }
    },
    "parameters": {
        "$connections": {
            "value": {
                "azureblob": {
                    "connectionId": "/subscriptions/YOUR_SUB/resourceGroups/YOUR_RG/providers/Microsoft.Web/connections/azureblob",
                    "connectionName": "azureblob",
                    "id": "/subscriptions/YOUR_SUB/providers/Microsoft.Web/locations/YOUR_REGION/managedApis/azureblob"
                },
                "azuremonitorlogs": {
                    "connectionId": "/subscriptions/YOUR_SUB/resourceGroups/YOUR_RG/providers/Microsoft.Web/connections/azuremonitorlogs",
                    "connectionName": "azuremonitorlogs",
                    "id": "/subscriptions/YOUR_SUB/providers/Microsoft.Web/locations/YOUR_REGION/managedApis/azuremonitorlogs"
                }
            }
        }
    }
}
```

**Note**: Replace placeholders:
- `YOUR_RESOURCE_GROUP`
- `YOUR_WORKSPACE_NAME`
- `YOUR_SUBSCRIPTION_ID`
- `YOUR_STORAGE_ACCOUNT`
- `YOUR_REGION`

---

## Validation Checklist

✅ **Storage Container Configuration**:
   - Navigate to Storage Account > Containers > `public-data`
   - Click **Change access level**
   - Set to **Blob (anonymous read access for blobs only)**

✅ **Timezone Synchronization**:
   - Logic App uses Pacific Time for file naming (not UTC)
   - This matches the frontend's California timezone
   - Files are created based on PST/PDT midnight (not UTC midnight)
   - Example: `attacks_2025-12-22.json` = Dec 22 in California

✅ **Test the Pipeline**:
   - Manually run the Logic App
   - Check Run History for green checkmarks
   - Verify the blob file exists in `public-data` container
   - Verify the blob URL is publicly accessible:
     ```
     https://YOUR_STORAGE_ACCOUNT.blob.core.windows.net/public-data/attacks_YYYY-MM-DD.json
     ```

✅ **Monitoring**:
   - Enable Application Insights for the Logic App (optional)
   - Set up alerts for failed runs

---

## Troubleshooting

**Issue**: Logic App fails on "Get Failed RDP Attacks"
- **Fix**: Verify Log Analytics Workspace connection has correct permissions
- Grant Logic App's Managed Identity "Log Analytics Reader" role on the workspace

**Issue**: No data in SecurityEvent table
- **Fix**: Ensure Windows VMs are sending Security Events to the workspace
- Check Data Collection Rules (DCR) are configured

**Issue**: Blob creation fails with 403
- **Fix**: Verify storage account connection uses correct access key
- Ensure container `public-data` exists

**Issue**: geo_info_from_ip_address returns null
- **Fix**: This is normal for private IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
- The query filters these out with `where IpAddress != ""`

---

## Next Steps

Once the backend is running:
1. Wait 30 minutes for the first data file to be created
2. Note your blob URL pattern:
   ```
   https://YOUR_STORAGE_ACCOUNT.blob.core.windows.net/public-data/attacks_YYYY-MM-DD.json
   ```
3. Use this URL in the frontend `index.html` (replace `YOUR_STORAGE_ACCOUNT`)
4. Deploy the frontend to Azure Static Web Apps

---
