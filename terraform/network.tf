# Networking Infrastructure
#
# Architecture:
#   ┌─────────────────────────────────────────────────────────┐
#   │                    Virtual Network                       │
#   │                    10.0.0.0/16                          │
#   │  ┌───────────────────────────────────────────────────┐  │
#   │  │              Subnet: 10.0.1.0/24                  │  │
#   │  │  ┌─────────────────────────────────────────────┐  │  │
#   │  │  │           Network Interface                  │  │  │
#   │  │  │     ┌─────────────┬─────────────┐           │  │  │
#   │  │  │     │ Private IP  │  Public IP  │           │  │  │
#   │  │  │     │  (Dynamic)  │  (Static)   │           │  │  │
#   │  │  │     └─────────────┴─────────────┘           │  │  │
#   │  │  └─────────────────────────────────────────────┘  │  │
#   │  └───────────────────────────────────────────────────┘  │
#   └─────────────────────────────────────────────────────────┘
#                              │
#                              ▼
#   ┌─────────────────────────────────────────────────────────┐
#   │              Network Security Group                      │
#   │     Allow RDP (3389) + All Inbound (Honeypot Config)    │
#   └─────────────────────────────────────────────────────────┘

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = var.vnet_address_space

  tags = var.tags
}

resource "azurerm_subnet" "subnet" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.subnet_address_prefixes
}

resource "azurerm_public_ip" "public_ip" {
  name                = "${var.vm_name}-ip"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = var.tags
}

# Network Security Group
# Intentionally permissive for honeypot attack surface

resource "azurerm_network_security_group" "nsg" {
  name                = "${var.vm_name}-nsg"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowRDP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = var.tags
}

resource "azurerm_network_interface" "nic" {
  name                = "${var.vm_name}-nic"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.public_ip.id
  }

  tags = var.tags
}

resource "azurerm_network_interface_security_group_association" "nsg_association" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}
