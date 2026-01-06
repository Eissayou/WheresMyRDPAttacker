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
  name                     = "${var.storage_account_name}func"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = var.tags
}

resource "azurerm_linux_function_app" "analysis" {
  name                = "honeypot-analysis-${random_string.suffix.result}"
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

    # Wildcard CORS for simplicity - restrict in production if needed
    cors {
      allowed_origins     = ["*"]
      support_credentials = false
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "python"
    AzureWebJobsFeatureFlags = "EnableWorkerIndexing" # Required for Python V2 decorator model
    GEMINI_API_KEY           = var.gemini_api_key
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

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
