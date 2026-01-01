# =====================================================
# PHASE 2: STORAGE ACCOUNT
# =====================================================
# This stores the attack data JSON files that your frontend reads.
#
# IMPORTANT: Storage account names must be:
# - Globally unique across ALL of Azure
# - 3-24 characters
# - Lowercase letters and numbers only (no dashes or underscores!)
#
# RESOURCE DEPENDENCIES:
# Notice how we reference the resource group we created in Phase 1:
#   resource_group_name = azurerm_resource_group.main.name
#                                                ↑
#                                          "main" = the resource group
#
# Terraform automatically understands this means:
# "Create the resource group FIRST, then create this storage account"
# This is called an IMPLICIT DEPENDENCY.

resource "azurerm_storage_account" "storage" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.main.name     # Reference to resource group!
  location                 = azurerm_resource_group.main.location # Same location as RG
  account_tier             = "Standard"                           # Standard or Premium
  account_replication_type = "LRS"                                # Locally Redundant Storage (cheapest)

  # This setting allows containers to have public access
  # Required for frontend to read attack data without authentication
  allow_nested_items_to_be_public = true

  tags = var.tags
}

# =====================================================
# BLOB CONTAINER
# =====================================================
# A container is like a folder inside the storage account.
# This holds the daily attack JSON files like:
#   attacks_2026-01-01.json
#   attacks_2026-01-02.json
#
# CONTAINER ACCESS TYPES:
# - "private"   = No anonymous access (need authentication)
# - "blob"      = Anonymous read for blobs only (what we need!)
# - "container" = Anonymous read for container AND blobs

resource "azurerm_storage_container" "public_data" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.storage.name # References storage account above
  container_access_type = "blob"                               # Anyone can read blobs (no auth needed)
}
