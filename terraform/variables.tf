# =====================================================
# INPUT VARIABLES
# =====================================================
# Variables make your Terraform code REUSABLE.
# Instead of hardcoding values, you define them here once
# and reference them everywhere with: var.variable_name
#
# Variables can have:
# - description: What it's for (shows in terraform plan)
# - type: string, number, bool, list, map, etc.
# - default: Value if none provided (optional)

variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "HONEYY-TF-TEST" # Test resource group (won't affect production!)
}

variable "location" {
  description = "Azure region where resources will be created"
  type        = string
  default     = "West US 2" # Your existing region
}

# Tags help you organize and track resources in Azure
# They show up in the Azure Portal and are useful for:
# - Cost tracking
# - Finding resources
# - Automation
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string) # A key-value map like {"Key": "Value"}
  default = {
    Project     = "HoneypotThreatMap"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# =====================================================
# PHASE 2: STORAGE VARIABLES
# =====================================================

variable "storage_account_name" {
  description = "Name of the storage account (must be globally unique, lowercase, no special chars)"
  type        = string
  default     = "jasonhoneypottest123"
}

# =====================================================
# PHASE 3: LOG ANALYTICS VARIABLES
# =====================================================

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  type        = string
  default     = "LogRepo" # Same as your existing workspace
}

variable "log_retention_days" {
  description = "Number of days to retain logs (30-730)"
  type        = number
  default     = 30 # Minimum is 30, saves money
}

# =====================================================
# PHASE 4: NETWORKING VARIABLES
# =====================================================

variable "vnet_name" {
  description = "Name of the virtual network"
  type        = string
  default     = "HoneyVM-vnet"
}

variable "vnet_address_space" {
  description = "Address space for the virtual network (CIDR notation)"
  type        = list(string)
  default     = ["10.0.0.0/16"] # 65,536 IP addresses
}

variable "subnet_address_prefixes" {
  description = "Address prefixes for the subnet (CIDR notation)"
  type        = list(string)
  default     = ["10.0.1.0/24"] # 256 IP addresses
}

# =====================================================
# PHASE 5: VIRTUAL MACHINE VARIABLES
# =====================================================

variable "vm_name" {
  description = "Name of the virtual machine"
  type        = string
  default     = "HoneyVM"
}

variable "vm_size" {
  description = "Size/SKU of the virtual machine"
  type        = string
  default     = "Standard_B1s" # Small, cheap burstable VM (~$7/month)
}

variable "admin_username" {
  description = "Admin username for the VM"
  type        = string
  default     = "azureuser"
}

# IMPORTANT: This variable has NO default value!
# You must provide it via:
#   - terraform.tfvars file (add to .gitignore!)
#   - Command line: terraform apply -var="admin_password=YourPass123!"
#   - Environment variable: TF_VAR_admin_password
variable "admin_password" {
  description = "Admin password for the VM (min 12 chars, uppercase, lowercase, number, special)"
  type        = string
  sensitive   = true # Won't show in logs or output
}
