# Input Variables

variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "HONEYY-TF-TEST"
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "West US 2"
}

variable "tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "HoneypotThreatMap"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Storage Configuration

variable "storage_account_name" {
  description = "Globally unique storage account name"
  type        = string
  default     = "jasonhoneypottest123"
}

# Log Analytics Configuration

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  type        = string
  default     = "LogRepo"
}

variable "log_retention_days" {
  description = "Log retention period in days (30-730)"
  type        = number
  default     = 30
}

# Networking Configuration

variable "vnet_name" {
  description = "Virtual network name"
  type        = string
  default     = "HoneyVM-vnet"
}

variable "vnet_address_space" {
  description = "Virtual network CIDR address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_address_prefixes" {
  description = "Subnet CIDR address prefixes"
  type        = list(string)
  default     = ["10.0.1.0/24"]
}

# Virtual Machine Configuration

variable "vm_name" {
  description = "Virtual machine name"
  type        = string
  default     = "HoneyVM"
}

variable "vm_size" {
  description = "Azure VM SKU"
  type        = string
  default     = "Standard_B1s"
}

variable "admin_username" {
  description = "VM administrator username"
  type        = string
  default     = "azureuser"
}

variable "admin_password" {
  description = "VM administrator password"
  type        = string
  sensitive   = true
}

variable "gemini_api_key" {
  description = "Gemini API key for LLM attack analysis"
  type        = string
  sensitive   = true
  default     = ""
}
