# Azure Function App - LLM Attack Analysis
#
# HTTP-triggered function for AI-powered attack comparison
# Uses Gemini API to analyze differences between two dates
#
# DEPLOYMENT NOTE:
# After terraform apply, deploy the function code with:
#   cd functions
#   func azure functionapp publish <function-app-name> --build remote
#
# IMPORTANT: Use --build remote (NOT --build local) when deploying from Mac!
# Local build downloads Mac wheels incompatible with Azure's Linux container.

resource "azurerm_service_plan" "functions" {
  name                = "honeypot-functions-plan"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption plan (pay per execution)

  tags = var.tags
}

resource "azurerm_storage_account" "functions" {
  name                       = "${var.storage_account_name}func"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  account_tier               = "Standard"
  account_replication_type   = "LRS"
  min_tls_version            = "TLS1_2"
  https_traffic_only_enabled = true

  tags = var.tags
}

resource "azurerm_linux_function_app" "analysis" {
  # Fixed name so the declared hostname mirrors the real deployed function the
  # frontend calls (https://aianalysis-...azurewebsites.net/api/compare). Azure
  # appends its own regional suffix to the base name.
  name                = "aianalysis"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key
  service_plan_id            = azurerm_service_plan.functions.id

  # Enable System Assigned Identity for Managed Identity access to Table Storage
  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.12"
    }

    # CORS is handled in application code (function_app.py sets an explicit
    # Access-Control-Allow-Origin and handles OPTIONS). Leaving the platform
    # CORS unset avoids duplicate/conflicting Access-Control-Allow-Origin headers.
    # The allowed origin is controlled by the ALLOWED_ORIGIN app setting below.
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME    = "python"
    FUNCTIONS_EXTENSION_VERSION = "~4"
    AzureWebJobsFeatureFlags    = "EnableWorkerIndexing" # Required for Python V2 decorator model
    GEMINI_API_KEY              = var.gemini_api_key
    # Origin allowed to call the AI endpoint (must match the deployed site URL).
    ALLOWED_ORIGIN = var.allowed_origin
    # Rate limiter fails closed by default to protect the paid Gemini quota.
    RATE_LIMIT_FAIL_OPEN = "false"
  }

  tags = var.tags
}

# Role assignment for Table Storage access via Managed Identity
# This allows the function to create/read the RateLimits table
resource "azurerm_role_assignment" "function_table_contributor" {
  scope                = azurerm_storage_account.functions.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = azurerm_linux_function_app.analysis.identity[0].principal_id
}
