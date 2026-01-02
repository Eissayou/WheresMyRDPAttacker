# Logic App - Data Parser
#
# Pipeline:
#   Timer (30 min) → KQL Query → Parse JSON → Write to Blob Storage
#
# NOTE: Azure Monitor Logs API connection requires manual OAuth authorization
#       after deployment. Navigate to: Portal → API Connections → Authorize

data "azurerm_subscription" "current" {}

locals {
  kql_query = <<-EOT
let timeOffset = 8h;
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

# API Connections

resource "azurerm_api_connection" "azuremonitorlogs" {
  name                = "azuremonitorlogs"
  resource_group_name = azurerm_resource_group.main.name
  managed_api_id      = "${data.azurerm_subscription.current.id}/providers/Microsoft.Web/locations/${azurerm_resource_group.main.location}/managedApis/azuremonitorlogs"
  display_name        = "Azure Monitor Logs"

  tags = var.tags
}

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

# Logic App Workflow

resource "azurerm_logic_app_workflow" "data_parser" {
  name                = "DataParser"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }

  workflow_parameters = {
    "$connections" = jsonencode({
      defaultValue = {}
      type         = "Object"
    })
  }

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

# Workflow Trigger & Actions

resource "azurerm_logic_app_trigger_recurrence" "every_30_min" {
  name         = "Recurrence"
  logic_app_id = azurerm_logic_app_workflow.data_parser.id
  frequency    = "Minute"
  interval     = 30
  time_zone    = "Pacific Standard Time"
}

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

# RBAC Role Assignments

resource "azurerm_role_assignment" "logic_app_log_reader" {
  scope                = azurerm_log_analytics_workspace.logs.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_logic_app_workflow.data_parser.identity[0].principal_id
}

resource "azurerm_role_assignment" "logic_app_blob_contributor" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_logic_app_workflow.data_parser.identity[0].principal_id
}
