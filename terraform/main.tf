# Resource Group
# Container for all honeypot infrastructure resources

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}
