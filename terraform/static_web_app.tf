# Static Web App
# Frontend hosting for the attack visualization map

resource "azurerm_static_web_app" "frontend" {
  name                = "WheresMyRDPAttacker"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  sku_tier            = "Free"
  sku_size            = "Free"

  # NOTE: Azure assigns the public hostname — the real site is served from
  # orange-wave-0061ed81e.6.azurestaticapps.net; it can't be set via Terraform.
  tags = var.tags
}
