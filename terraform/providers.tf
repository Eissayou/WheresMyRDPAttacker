# =====================================================
# TERRAFORM CONFIGURATION BLOCK
# =====================================================
# This tells Terraform:
# 1. What version of Terraform to use
# 2. What providers (cloud plugins) we need
#
# Think of providers like drivers - they let Terraform
# "talk" to Azure's API to create resources.

terraform {
  # Require Terraform 1.0 or higher
  required_version = ">= 1.0.0"

  # Declare the providers we need
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm" # Official Azure provider by HashiCorp
      version = "~> 3.0"            # Use any 3.x version (3.0, 3.1, etc.)
    }
  }
}

# =====================================================
# AZURE PROVIDER CONFIGURATION
# =====================================================
# This configures HOW Terraform connects to Azure.
# 
# By default, it uses your Azure CLI credentials (from `az login`).
# The "features {}" block is required but can be empty.

provider "azurerm" {
  features {}

  # Terraform will use your default subscription from `az login`
  # You can explicitly set it if you have multiple subscriptions
}
