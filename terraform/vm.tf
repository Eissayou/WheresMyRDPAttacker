# Windows Virtual Machine (Honeypot)
#
# Data Flow:
#   Attackers → RDP (3389) → VM → Security Events → AMA → DCR → Log Analytics

resource "azurerm_windows_virtual_machine" "vm" {
  name                = var.vm_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = var.vm_size
  admin_username      = var.admin_username
  admin_password      = var.admin_password

  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    name                 = "${var.vm_name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.storage.primary_blob_endpoint
  }

  tags = var.tags
}

# Disable Windows Firewall
# Maximizes attack surface for honeypot data collection

resource "azurerm_virtual_machine_extension" "disable_firewall" {
  name                 = "disable-windows-firewall"
  virtual_machine_id   = azurerm_windows_virtual_machine.vm.id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  settings = jsonencode({
    commandToExecute = "powershell -Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False\""
  })

  tags = var.tags
}

# Azure Monitor Agent (AMA)
# Collects Windows Security Events for failed login analysis

resource "azurerm_virtual_machine_extension" "azure_monitor_agent" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.vm.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  automatic_upgrade_enabled  = true
  auto_upgrade_minor_version = true

  tags = var.tags

  depends_on = [azurerm_virtual_machine_extension.disable_firewall]
}

# Data Collection Rule
# Routes Windows Security Events (Event ID 4625) to Log Analytics

resource "azurerm_monitor_data_collection_rule" "security_events" {
  name                = "dcr-security-events"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.logs.id
      name                  = "log-analytics-destination"
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["log-analytics-destination"]
  }

  data_sources {
    windows_event_log {
      name           = "security-events"
      streams        = ["Microsoft-SecurityEvent"]
      x_path_queries = ["Security!*"]
    }
  }

  tags = var.tags
}

resource "azurerm_monitor_data_collection_rule_association" "vm_dcr" {
  name                    = "dcr-association"
  target_resource_id      = azurerm_windows_virtual_machine.vm.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.security_events.id

  depends_on = [azurerm_virtual_machine_extension.azure_monitor_agent]
}
