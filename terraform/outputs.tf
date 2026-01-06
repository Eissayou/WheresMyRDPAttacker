# Outputs

# Resource Group
output "resource_group_name" {
  description = "Resource group name"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "Resource group ID"
  value       = azurerm_resource_group.main.id
}

# Storage
output "storage_account_name" {
  description = "Storage account name"
  value       = azurerm_storage_account.storage.name
}

output "storage_blob_endpoint" {
  description = "Blob storage endpoint URL"
  value       = azurerm_storage_account.storage.primary_blob_endpoint
}

output "attack_data_url" {
  description = "Attack data file URL pattern"
  value       = "${azurerm_storage_account.storage.primary_blob_endpoint}public-data/attacks_YYYY-MM-DD.json"
}

# Log Analytics
output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = azurerm_log_analytics_workspace.logs.id
}

output "log_analytics_workspace_workspace_id" {
  description = "Log Analytics workspace ID (for agent configuration)"
  value       = azurerm_log_analytics_workspace.logs.workspace_id
}

output "log_analytics_workspace_key" {
  description = "Log Analytics primary shared key"
  value       = azurerm_log_analytics_workspace.logs.primary_shared_key
  sensitive   = true
}

# Networking
output "public_ip_address" {
  description = "Honeypot public IP address"
  value       = azurerm_public_ip.public_ip.ip_address
}

output "vnet_name" {
  description = "Virtual network name"
  value       = azurerm_virtual_network.vnet.name
}

output "subnet_id" {
  description = "Subnet ID"
  value       = azurerm_subnet.subnet.id
}

output "nic_id" {
  description = "Network interface ID"
  value       = azurerm_network_interface.nic.id
}

# Virtual Machine
output "vm_name" {
  description = "Virtual machine name"
  value       = azurerm_windows_virtual_machine.vm.name
}

output "vm_id" {
  description = "Virtual machine resource ID"
  value       = azurerm_windows_virtual_machine.vm.id
}

output "rdp_connection_string" {
  description = "RDP connection endpoint"
  value       = "${azurerm_public_ip.public_ip.ip_address}:3389"
}

# Logic App
output "logic_app_name" {
  description = "Logic App name"
  value       = azurerm_logic_app_workflow.data_parser.name
}

output "logic_app_id" {
  description = "Logic App resource ID"
  value       = azurerm_logic_app_workflow.data_parser.id
}

output "logic_app_identity_principal_id" {
  description = "Logic App managed identity principal ID"
  value       = azurerm_logic_app_workflow.data_parser.identity[0].principal_id
}

# Static Web App
output "static_web_app_name" {
  description = "Static Web App name"
  value       = azurerm_static_web_app.frontend.name
}

output "static_web_app_url" {
  description = "Static Web App default URL"
  value       = azurerm_static_web_app.frontend.default_host_name
}

output "static_web_app_api_key" {
  description = "Static Web App deployment API key"
  value       = azurerm_static_web_app.frontend.api_key
  sensitive   = true
}

# Function App
output "function_app_name" {
  description = "Function App name (use with: func azure functionapp publish <name> --build remote)"
  value       = azurerm_linux_function_app.analysis.name
}

output "function_app_url" {
  description = "Function App URL for AI analysis"
  value       = "https://${azurerm_linux_function_app.analysis.default_hostname}/api/compare"
}
