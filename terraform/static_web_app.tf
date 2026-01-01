# =====================================================
# PHASE 7: STATIC WEB APP
# =====================================================
# This hosts your frontend - the index.html that displays
# the attack map using Leaflet.js.
#
# Azure Static Web Apps:
# - Host static content (HTML, CSS, JS)
# - Free tier available
# - Built-in CI/CD with GitHub Actions
# - Global CDN for fast loading
#
# HOW IT WORKS:
# 1. You push code to GitHub (index.html)
# 2. GitHub Actions automatically deploys to Azure
# 3. Users visit the URL and see the map
# 4. The map fetches attack data from blob storage

resource "azurerm_static_web_app" "frontend" {
  name                = "WheresMyRDPAttacker"
  resource_group_name = azurerm_resource_group.main.name

  # Static Web Apps have limited region availability
  # West US 2 is one of the supported regions
  location = "westus2"

  # Free tier is sufficient for this project
  sku_tier = "Free"
  sku_size = "Free"

  tags = var.tags
}

# =====================================================
# GITHUB INTEGRATION NOTE
# =====================================================
# After terraform apply, you need to connect GitHub:
#
# OPTION 1: Azure Portal
#   1. Go to the Static Web App in Azure Portal
#   2. Click "Manage deployment token"
#   3. Copy the token
#   4. Add as GitHub secret: AZURE_STATIC_WEB_APPS_API_TOKEN
#   5. Create GitHub Actions workflow (see your repo's .github/workflows)
#
# OPTION 2: Use the output token
#   The api_key output below is the deployment token
#   You can use: terraform output -raw static_web_app_api_key
#
# NOTE: You already have this set up with your existing Static Web App!
# The index.html in your repo automatically deploys when you push.
