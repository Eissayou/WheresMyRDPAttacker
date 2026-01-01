# =====================================================
# PHASE 4: NETWORKING
# =====================================================
# This creates all the network infrastructure for the honeypot VM.
#
# ARCHITECTURE:
#   Internet
#      │
#      ▼
#   [Public IP] ─── Attackers connect here
#      │
#      ▼
#   [Network Security Group] ─── Allows ALL traffic (honeypot!)
#      │
#      ▼
#   [Network Interface] ─── Connects VM to network
#      │
#      ▼
#   [Subnet] ─── 10.0.1.0/24
#      │
#      ▼
#   [Virtual Network] ─── 10.0.0.0/16

# =====================================================
# VIRTUAL NETWORK (VNet)
# =====================================================
# The private network container. Think of it as your own
# isolated network in Azure's data center.
#
# CIDR Notation: 10.0.0.0/16 means:
# - Network: 10.0.x.x
# - Available IPs: 65,536 addresses

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = var.vnet_address_space # ["10.0.0.0/16"]

  tags = var.tags
}

# =====================================================
# SUBNET
# =====================================================
# A segment of the VNet. VMs connect to subnets, not directly to VNets.
#
# CIDR Notation: 10.0.1.0/24 means:
# - Network: 10.0.1.x
# - Available IPs: 256 addresses (251 usable, Azure reserves 5)

resource "azurerm_subnet" "subnet" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet.name # Must be in this VNet
  address_prefixes     = var.subnet_address_prefixes       # ["10.0.1.0/24"]
}

# =====================================================
# PUBLIC IP ADDRESS
# =====================================================
# This is the IP address exposed to the internet.
# Attackers will target this IP to try RDP connections.
#
# Allocation Methods:
# - "Static"  = IP never changes (even after VM restart)
# - "Dynamic" = IP can change on restart

resource "azurerm_public_ip" "public_ip" {
  name                = "HoneyVM-ip"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  allocation_method   = "Static"   # IP stays the same
  sku                 = "Standard" # Required for some features

  tags = var.tags
}

# =====================================================
# NETWORK SECURITY GROUP (NSG)
# =====================================================
# This is the FIREWALL for the network.
# For a honeypot, we ALLOW all traffic to attract attackers!

resource "azurerm_network_security_group" "nsg" {
  name                = "HoneyVM-nsg"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  # Rule 1: Allow RDP from anywhere
  # This is the main honeypot trap - port 3389 wide open!
  security_rule {
    name                       = "AllowRDP"
    priority                   = 100 # Lower number = higher priority
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"    # Any source port
    destination_port_range     = "3389" # RDP port
    source_address_prefix      = "*"    # Any IP address
    destination_address_prefix = "*"    # Any destination
  }

  # Rule 2: Allow ALL other inbound traffic
  # Maximum exposure for the honeypot
  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*" # Any protocol
    source_port_range          = "*"
    destination_port_range     = "*" # Any port
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = var.tags
}

# =====================================================
# NETWORK INTERFACE (NIC)
# =====================================================
# This connects the VM to the network.
# It has:
# - A private IP (internal, in the subnet)
# - A public IP (external, for internet access)

resource "azurerm_network_interface" "nic" {
  name                = "HoneyVM-nic"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id       # Connect to our subnet
    private_ip_address_allocation = "Dynamic"                      # Azure assigns IP
    public_ip_address_id          = azurerm_public_ip.public_ip.id # Attach public IP
  }

  tags = var.tags
}

# =====================================================
# ASSOCIATE NSG WITH NIC
# =====================================================
# This applies the security rules to the network interface.
# Without this, the NSG rules don't do anything!

resource "azurerm_network_interface_security_group_association" "nsg_association" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}
