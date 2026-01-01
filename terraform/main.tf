# =====================================================
# RESOURCE GROUP
# =====================================================
# A Resource Group is a CONTAINER for Azure resources.
# All resources in this project will live inside this group.
#
# SYNTAX BREAKDOWN:
#   resource "azurerm_resource_group" "main" {
#            │                        │
#            │                        └── Local name (your reference)
#            └── Resource type from Azure provider
#
# You reference this resource elsewhere as:
#   azurerm_resource_group.main.name
#   azurerm_resource_group.main.location
#   azurerm_resource_group.main.id

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name # Uses the variable we defined
  location = var.location            # Uses the variable we defined
  tags     = var.tags                # Applies all our tags
}
