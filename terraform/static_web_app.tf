# Static Web App
# Frontend hosting for the attack visualization map

resource "azurerm_static_web_app" "frontend" {
  name                = "WheresMyRDPAttacker"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  sku_tier            = "Free"
  sku_size            = "Free"

  # NOTE: Azure assigns the default hostname
  # (orange-wave-0061ed81e.6.azurestaticapps.net); it can't be set via
  # Terraform. The branded domain is the custom-domain resource below.
  tags = var.tags
}

# Branded subdomain. DNS lives in Cloudflare (unproxied CNAME honeypot ->
# orange-wave-0061ed81e.6.azurestaticapps.net); Azure issues the managed cert.
# The domain was bound via the az CLI; if this config is ever applied for real,
# import this resource first. The API doesn't return validation_type, so it is
# ignored to avoid a perpetual diff after import.
resource "azurerm_static_web_app_custom_domain" "honeypot" {
  static_web_app_id = azurerm_static_web_app.frontend.id
  domain_name       = "honeypot.eissayou.com"
  validation_type   = "cname-delegation"

  lifecycle {
    ignore_changes = [validation_type]
  }
}
