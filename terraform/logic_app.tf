# =====================================================
# PHASE 6: LOGIC APP (DATA PARSER)
# =====================================================
# This Logic App is the "glue" that:
# 1. Runs on a schedule (every 30 minutes)
# 2. Queries Log Analytics for failed RDP attempts
# 3. Parses the results
# 4. Writes the results as JSON to blob storage
# 5. The frontend reads this JSON to display the map

# =====================================================
# DATA: CURRENT SUBSCRIPTION
# =====================================================

data "azurerm_subscription" "current" {}

# =====================================================
# LOCAL VALUES FOR WORKFLOW DEFINITION
# =====================================================
# We use locals to build the workflow JSON with dynamic values

locals {
  # KQL query to get failed RDP attempts with geo data
  kql_query = <<-EOT
// PST (UTC-8). Note: this is not DST-aware (PDT would be UTC-7).
let timeOffset = 8h;

// Start-of-day in PST, converted back to UTC for filtering TimeGenerated
let lookbackTimeUtc = startofday(now() - timeOffset) + timeOffset;

SecurityEvent
| where TimeGenerated >= lookbackTimeUtc
| where EventID == 4625
| where AccountType == "User"
| where IpAddress !in ("-", "::1", "127.0.0.1")
| extend GeoData = geo_info_from_ip_address(IpAddress)
| project
    TimeGenerated,
    IpAddress,
    Country = tostring(GeoData.country),
    State = tostring(GeoData.state),
    City = tostring(GeoData.city),
    Latitude = todouble(GeoData.latitude),
    Longitude = todouble(GeoData.longitude),
    Computer,
    Account
| summarize
    AttackCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetAccounts = make_set(Account, 10),
    TargetComputers = make_set(Computer, 5)
  by IpAddress, Country, State, City, Latitude, Longitude
| project
    ip = tostring(IpAddress),
    country = tostring(Country),
    state = tostring(State),
    city = tostring(City),
    lat = todouble(Latitude),
    lon = todouble(Longitude),
    attack_count = toint(AttackCount),
    first_seen = tostring(FirstSeen),
    last_seen = tostring(LastSeen),
    target_accounts = tostring(TargetAccounts),
    target_computers = tostring(TargetComputers)
| order by attack_count desc
EOT
}

# =====================================================
# API CONNECTION: AZURE MONITOR LOGS
# =====================================================
# IMPORTANT: This connector requires MANUAL AUTHORIZATION!
#
# After terraform apply, you must:
# 1. Go to Azure Portal → API Connections → "azuremonitorlogs"
# 2. Click "Edit API connection"
# 3. Click "Authorize" and sign in with your Azure account
# 4. Click "Save"
#
# This is a limitation of the Azure Monitor Logs connector - it does
# not support access key or managed identity authentication through
# Terraform. This is a one-time manual step.

resource "azurerm_api_connection" "azuremonitorlogs" {
  name                = "azuremonitorlogs"
  resource_group_name = azurerm_resource_group.main.name
  managed_api_id      = "${data.azurerm_subscription.current.id}/providers/Microsoft.Web/locations/${azurerm_resource_group.main.location}/managedApis/azuremonitorlogs"
  display_name        = "Azure Monitor Logs"

  tags = var.tags
}


# =====================================================
# API CONNECTION: AZURE BLOB STORAGE
# =====================================================

resource "azurerm_api_connection" "azureblob" {
  name                = "azureblob"
  resource_group_name = azurerm_resource_group.main.name
  managed_api_id      = "${data.azurerm_subscription.current.id}/providers/Microsoft.Web/locations/${azurerm_resource_group.main.location}/managedApis/azureblob"
  display_name        = "Azure Blob Storage"

  parameter_values = {
    accountName = azurerm_storage_account.storage.name
    accessKey   = azurerm_storage_account.storage.primary_access_key
  }

  tags = var.tags
}

# =====================================================
# LOGIC APP WORKFLOW
# =====================================================

resource "azurerm_logic_app_workflow" "data_parser" {
  name                = "DataParser"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }

  # Connection parameters - tells the workflow which connections to use
  workflow_parameters = {
    "$connections" = jsonencode({
      defaultValue = {}
      type         = "Object"
    })
  }

  # The parameters that will be passed at runtime
  parameters = {
    "$connections" = jsonencode({
      azuremonitorlogs = {
        id             = azurerm_api_connection.azuremonitorlogs.managed_api_id
        connectionId   = azurerm_api_connection.azuremonitorlogs.id
        connectionName = azurerm_api_connection.azuremonitorlogs.name
      }
      azureblob = {
        id             = azurerm_api_connection.azureblob.managed_api_id
        connectionId   = azurerm_api_connection.azureblob.id
        connectionName = azurerm_api_connection.azureblob.name
      }
    })
  }

  tags = var.tags
}

# =====================================================
# LOGIC APP TRIGGER: RECURRENCE
# =====================================================
# Runs every 30 minutes

resource "azurerm_logic_app_trigger_recurrence" "every_30_min" {
  name         = "Recurrence"
  logic_app_id = azurerm_logic_app_workflow.data_parser.id
  frequency    = "Minute"
  interval     = 30
  time_zone    = "Pacific Standard Time"
}

# =====================================================
# LOGIC APP ACTION: RUN QUERY
# =====================================================
# Queries Log Analytics for failed RDP attempts

resource "azurerm_logic_app_action_custom" "run_query" {
  name         = "Run_query_and_list_results"
  logic_app_id = azurerm_logic_app_workflow.data_parser.id

  body = jsonencode({
    type = "ApiConnection"
    inputs = {
      host = {
        connection = {
          name = "@parameters('$connections')['azuremonitorlogs']['connectionId']"
        }
      }
      method = "post"
      body   = local.kql_query
      path   = "/queryData"
      queries = {
        subscriptions  = data.azurerm_subscription.current.subscription_id
        resourcegroups = azurerm_resource_group.main.name
        resourcetype   = "Log Analytics Workspace"
        resourcename   = azurerm_log_analytics_workspace.logs.name
        timerange      = "Set in query"
      }
    }
  })

  depends_on = [azurerm_logic_app_trigger_recurrence.every_30_min]
}

# =====================================================
# LOGIC APP ACTION: PARSE JSON
# =====================================================
# Parses the query results into structured objects

resource "azurerm_logic_app_action_custom" "parse_json" {
  name         = "Parse_JSON"
  logic_app_id = azurerm_logic_app_workflow.data_parser.id

  body = jsonencode({
    type = "ParseJson"
    inputs = {
      content = "@body('Run_query_and_list_results')"
      schema = {
        type = "object"
        properties = {
          value = {
            type = "array"
            items = {
              type = "object"
              properties = {
                ip               = { type = "string" }
                country          = { type = "string" }
                state            = { type = "string" }
                city             = { type = "string" }
                lat              = { type = "number" }
                lon              = { type = "number" }
                attack_count     = { type = "integer" }
                first_seen       = { type = "string" }
                last_seen        = { type = "string" }
                target_accounts  = { type = "string" }
                target_computers = { type = "string" }
              }
            }
          }
        }
      }
    }
    runAfter = {
      Run_query_and_list_results = ["Succeeded"]
    }
  })

  depends_on = [azurerm_logic_app_action_custom.run_query]
}

# =====================================================
# LOGIC APP ACTION: CREATE BLOB
# =====================================================
# Writes the parsed data to blob storage

resource "azurerm_logic_app_action_custom" "create_blob" {
  name         = "Create_blob_V2"
  logic_app_id = azurerm_logic_app_workflow.data_parser.id

  body = jsonencode({
    type = "ApiConnection"
    inputs = {
      host = {
        connection = {
          name = "@parameters('$connections')['azureblob']['connectionId']"
        }
      }
      method = "post"
      body   = "@body('Parse_JSON')?['value']"
      headers = {
        ReadFileMetadataFromServer = true
      }
      path = "/v2/datasets/@{encodeURIComponent(encodeURIComponent('AccountNameFromSettings'))}/files"
      queries = {
        folderPath                   = "/public-data"
        name                         = "@concat('attacks_', convertTimeZone(utcNow(), 'UTC', 'Pacific Standard Time', 'yyyy-MM-dd'), '.json')"
        queryParametersSingleEncoded = true
      }
    }
    runtimeConfiguration = {
      contentTransfer = {
        transferMode = "Chunked"
      }
    }
    runAfter = {
      Parse_JSON = ["Succeeded"]
    }
  })

  depends_on = [azurerm_logic_app_action_custom.parse_json]
}

# =====================================================
# ROLE ASSIGNMENT: LOG ANALYTICS READER
# =====================================================

resource "azurerm_role_assignment" "logic_app_log_reader" {
  scope                = azurerm_log_analytics_workspace.logs.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_logic_app_workflow.data_parser.identity[0].principal_id
}

# =====================================================
# ROLE ASSIGNMENT: STORAGE BLOB DATA CONTRIBUTOR
# =====================================================

resource "azurerm_role_assignment" "logic_app_blob_contributor" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_logic_app_workflow.data_parser.identity[0].principal_id
}
