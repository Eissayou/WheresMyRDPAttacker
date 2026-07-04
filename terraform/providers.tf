# Terraform and Azure Provider Configuration

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116"
    }
  }

  # State handling is intentional but "for show": this config has never been applied.
  # If it ever is, store state remotely (never local — it would contain the storage
  # keys, VM password and SWA token in plaintext). Example:
  #
  # backend "azurerm" {
  #   resource_group_name  = "tfstate-rg"
  #   storage_account_name = "honeypottfstate"
  #   container_name       = "tfstate"
  #   key                  = "honeypot.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  features {}
}
