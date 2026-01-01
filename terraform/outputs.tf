# =====================================================
# OUTPUTS
# =====================================================
# Outputs display values AFTER `terraform apply` completes.
# They're useful for:
# 1. Seeing important info (IDs, URLs, IPs)
# 2. Passing values to other Terraform configurations
# 3. Using in scripts with `terraform output <name>`
#
# SYNTAX:
#   output "name" {
#     value = <expression>
#   }

# =====================================================
# PHASE 1: RESOURCE GROUP OUTPUTS
# =====================================================

output "resource_group_name" {
  description = "The name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "The Azure ID of the resource group"
  value       = azurerm_resource_group.main.id
}

output "resource_group_location" {
  description = "The Azure region of the resource group"
  value       = azurerm_resource_group.main.location
}

# =====================================================
# PHASE 2: STORAGE OUTPUTS
# =====================================================

output "storage_account_name" {
  description = "The name of the storage account"
  value       = azurerm_storage_account.storage.name
}

output "storage_blob_endpoint" {
  description = "The primary blob endpoint URL"
  value       = azurerm_storage_account.storage.primary_blob_endpoint
}

output "attack_data_url" {
  description = "URL pattern for accessing attack data files"
  value       = "${azurerm_storage_account.storage.primary_blob_endpoint}public-data/attacks_YYYY-MM-DD.json"
}

# =====================================================
# PHASE 3: LOG ANALYTICS OUTPUTS
# =====================================================

output "log_analytics_workspace_id" {
  description = "The full Azure resource ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.logs.id
}

output "log_analytics_workspace_workspace_id" {
  description = "The Workspace ID (used for agent configuration)"
  value       = azurerm_log_analytics_workspace.logs.workspace_id
}

# NOTE: The workspace key is sensitive - it's used to authenticate
# agents sending data to the workspace. We mark it sensitive so
# it doesn't show in terraform output by default.
output "log_analytics_workspace_key" {
  description = "The primary shared key for the workspace (sensitive)"
  value       = azurerm_log_analytics_workspace.logs.primary_shared_key
  sensitive   = true # Won't display in console output
}

# =====================================================
# PHASE 4: NETWORKING OUTPUTS
# =====================================================

output "public_ip_address" {
  description = "The public IP address of the honeypot (attackers target this)"
  value       = azurerm_public_ip.public_ip.ip_address
}

output "vnet_name" {
  description = "The name of the virtual network"
  value       = azurerm_virtual_network.vnet.name
}

output "subnet_id" {
  description = "The ID of the subnet"
  value       = azurerm_subnet.subnet.id
}

output "nic_id" {
  description = "The ID of the network interface"
  value       = azurerm_network_interface.nic.id
}

# =====================================================
# PHASE 5: VIRTUAL MACHINE OUTPUTS
# =====================================================

output "vm_name" {
  description = "The name of the virtual machine"
  value       = azurerm_windows_virtual_machine.vm.name
}

output "vm_id" {
  description = "The Azure resource ID of the VM"
  value       = azurerm_windows_virtual_machine.vm.id
}

output "rdp_connection_string" {
  description = "RDP connection string (IP:Port)"
  value       = "${azurerm_public_ip.public_ip.ip_address}:3389"
}

# =====================================================
# PHASE 6: LOGIC APP OUTPUTS
# =====================================================

output "logic_app_name" {
  description = "The name of the Logic App"
  value       = azurerm_logic_app_workflow.data_parser.name
}

output "logic_app_id" {
  description = "The Azure resource ID of the Logic App"
  value       = azurerm_logic_app_workflow.data_parser.id
}

output "logic_app_identity_principal_id" {
  description = "The principal ID of the Logic App's managed identity"
  value       = azurerm_logic_app_workflow.data_parser.identity[0].principal_id
}

# =====================================================
# PHASE 7: STATIC WEB APP OUTPUTS
# =====================================================

output "static_web_app_name" {
  description = "The name of the Static Web App"
  value       = azurerm_static_web_app.frontend.name
}

output "static_web_app_url" {
  description = "The default URL of the Static Web App"
  value       = azurerm_static_web_app.frontend.default_host_name
}

output "static_web_app_api_key" {
  description = "The API key for GitHub Actions deployment (sensitive)"
  value       = azurerm_static_web_app.frontend.api_key
  sensitive   = true
}
