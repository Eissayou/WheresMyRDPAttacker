# =====================================================
# PHASE 5: VIRTUAL MACHINE
# =====================================================
# This is the actual honeypot - a Windows VM with RDP exposed.
#
# HOW IT WORKS:
# 1. Attackers find the public IP (from scans or shodan)
# 2. They try to brute-force RDP login (port 3389)
# 3. Windows logs every failed attempt as Event ID 4625
# 4. The Azure Monitor Agent sends these logs to our workspace
# 5. The Logic App queries the logs and writes attack data to blob
#
# VM SIZE: Standard_B1s
# - 1 vCPU, 1 GB RAM
# - Burstable (good for low/variable workloads)
# - ~$7/month (cheapest Windows VM)

resource "azurerm_windows_virtual_machine" "vm" {
  name                = var.vm_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = var.vm_size # "Standard_B1s"
  admin_username      = var.admin_username
  admin_password      = var.admin_password # Sensitive!

  # Connect to our network interface (which has the public IP)
  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  # Enable System Assigned Managed Identity
  # Required for AMA to authenticate to Azure
  identity {
    type = "SystemAssigned"
  }

  # OS Disk configuration
  os_disk {
    name                 = "${var.vm_name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS" # Cheapest disk type
  }

  # Windows Server 2022 image
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  # Enable boot diagnostics (helps troubleshoot boot issues)
  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.storage.primary_blob_endpoint
  }

  tags = var.tags
}

# =====================================================
# VM EXTENSION: DISABLE WINDOWS FIREWALL
# =====================================================
# This runs a PowerShell command AFTER the VM is created.
# It disables the Windows Firewall on all profiles so
# attackers can connect without any OS-level blocking.

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

# =====================================================
# VM EXTENSION: AZURE MONITOR AGENT (AMA)
# =====================================================
# This installs the modern Azure Monitor Agent on the VM.
# AMA replaced the old MMA (Microsoft Monitoring Agent) which
# was deprecated in August 2024.
#
# NOTE: AMA alone doesn't collect anything - it needs a
# Data Collection Rule (DCR) to tell it what to collect!

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

# =====================================================
# DATA COLLECTION RULE (DCR)
# =====================================================
# This tells the Azure Monitor Agent:
# - WHAT to collect (Windows Security Events)
# - WHERE to send it (Log Analytics Workspace)
#
# This is the modern replacement for the old MMA approach!

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
      name    = "security-events"
      streams = ["Microsoft-SecurityEvent"]
      # Collect Security events including failed logins (4625)
      x_path_queries = ["Security!*"]
    }
  }

  tags = var.tags
}

# =====================================================
# DATA COLLECTION RULE ASSOCIATION
# =====================================================
# This links the DCR to the VM.
# Without this, the agent won't know which rules apply to it!

resource "azurerm_monitor_data_collection_rule_association" "vm_dcr" {
  name                    = "dcr-association"
  target_resource_id      = azurerm_windows_virtual_machine.vm.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.security_events.id

  depends_on = [azurerm_virtual_machine_extension.azure_monitor_agent]
}
