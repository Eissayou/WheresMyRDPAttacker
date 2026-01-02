# Static Web App
# Frontend hosting for the attack visualization map

resource "azurerm_static_web_app" "frontend" {
  name                = "WheresMyRDPAttacker"
  resource_group_name = azurerm_resource_group.main.name
  location            = "westus2"
  sku_tier            = "Free"
  sku_size            = "Free"

  tags = var.tags
}
