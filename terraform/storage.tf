# Storage Account
# Hosts publicly accessible attack data JSON files for frontend consumption

resource "azurerm_storage_account" "storage" {
  name                            = var.storage_account_name
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true

  tags = var.tags
}

# Blob Container
# Public read access for attack data files (attacks_YYYY-MM-DD.json)

resource "azurerm_storage_container" "public_data" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.storage.name
  container_access_type = "blob"
}
