# =====================================================
# PHASE 3: LOG ANALYTICS WORKSPACE
# =====================================================
# Log Analytics is where your honeypot VM sends its logs.
# The Logic App queries this workspace to find failed RDP attempts.
#
# WHAT IT STORES:
# - SecurityEvent logs (Event ID 4625 = failed login)
# - Performance data
# - Custom logs
#
# PRICING:
# - "PerGB2018" = Pay per GB of data ingested
# - First 5GB/month is free
# - Retention: 30 days free, pay for more

resource "azurerm_log_analytics_workspace" "logs" {
  name                = var.log_analytics_workspace_name
  resource_group_name = azurerm_resource_group.main.name     # Reference to resource group
  location            = azurerm_resource_group.main.location # Same location as RG
  sku                 = "PerGB2018"                          # Pay-per-GB pricing (most common)
  retention_in_days   = var.log_retention_days

  tags = var.tags
}

# =====================================================
# UNDERSTANDING LOG ANALYTICS
# =====================================================
# After this is created, you can:
#
# 1. Send logs from VMs using the "Log Analytics Agent" 
#    (we'll do this in Phase 5 with a VM extension)
#
# 2. Query logs using KQL (Kusto Query Language)
#    Example: SecurityEvent | where EventID == 4625
#
# 3. The Logic App (Phase 6) will query this workspace
#    to get failed RDP attempts and write them to blob storage
