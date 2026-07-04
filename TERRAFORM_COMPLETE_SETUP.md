# Terraform Complete Setup: Azure Honeypot Infrastructure


**Last Updated**: July 2026

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Project Structure](#project-structure)
4. [Quick Start](#quick-start)
5. [Phase Reference](#phase-reference)
6. [Post-Deployment Steps](#post-deployment-steps)
7. [Command Reference](#command-reference)
8. [Key Concepts](#key-concepts)

---

## Overview

### What This Terraform Creates

| Resource | Type | Purpose |
|----------|------|---------|
| `HONEYY` | Resource Group | Container for all resources |
| `honeypotpublicdata` | Storage Account | Stores attack JSON data |
| `public-data` | Blob Container | Holds daily attack files |
| `LogRepo` | Log Analytics Workspace | Collects SecurityEvent logs |
| `HoneyVM-vnet` | Virtual Network | Network for the VM |
| `HoneyVM-ip` | Public IP | Public-facing IP for attacks |
| `HoneyVM-nsg` | NSG | Allows all traffic (honeypot!) |
| `HoneyVM` | Windows VM | Honeypot with RDP exposed |
| `dcr-security-events` | Data Collection Rule | Sends Security Events to Log Analytics |
| `DataParser` | Logic App | Runs KQL query, writes to blob |
| `WheresMyRDPAttacker` | Static Web App | Frontend dashboard |
| `AIAnalysis` | Function App (Python) | AI trend analysis via Gemini |
| `ASP-HONEYY-9ec3` | Service Plan | Consumption plan for the Function App |
| `honeyya865` | Storage Account | Function App backing storage |
| `RateLimits` | Table (Table Storage) | Per-IP / global AI rate-limit counters |

### Architecture Flow

```
Attackers ──► RDP (3389) ──► HoneyVM ──► Windows Security Events
                                              │
                                              ▼
                              Azure Monitor Agent (AMA)
                                              │
                                              ▼
                              Data Collection Rule (DCR)
                                              │
                                              ▼
                              Log Analytics Workspace
                                              │
                                              ▼
                                    Logic App (KQL Query)
                                              │
                                              ▼
                              Blob Storage (attacks.json)
                                              │
                                              ▼
                              Static Web App (Map Frontend)
```

---

## Prerequisites

### 1. Install Terraform
```bash
brew install terraform
terraform --version  # Should be >= 1.0.0
```

### 2. Install & Login to Azure CLI
```bash
brew install azure-cli
az login
az account show --query "{Name:name, ID:id}" -o table
```

### 3. Subscription ID
```
Subscription ID: <your-azure-subscription-id>
```
> Find yours with `az account show --query id -o tsv`. Never commit the real value.

---

## Project Structure

```
WheresMyRDPAttacker/
├── terraform/
│   ├── .gitignore              # Protects state files from Git
│   ├── providers.tf            # Terraform & Azure provider config
│   ├── variables.tf            # All input variables
│   ├── outputs.tf              # Output values after apply
│   ├── main.tf                 # Resource Group (Phase 1)
│   ├── storage.tf              # Storage Account + Container (Phase 2)
│   ├── log_analytics.tf        # Log Analytics Workspace (Phase 3)
│   ├── network.tf              # VNet, Subnet, NSG, IP, NIC (Phase 4)
│   ├── vm.tf                   # VM + Extensions + DCR (Phase 5)
│   ├── logic_app.tf            # Logic App + Connections (Phase 6)
│   ├── static_web_app.tf       # Frontend hosting (Phase 7)
│   ├── function.tf             # AI Function App + Table Storage (Phase 8)
│   └── terraform.tfvars        # Secrets (gitignored!)
├── app/                        # Static site (published web root)
│   ├── index.html              # Frontend map + SEO
│   ├── css/main.css            # Styles
│   └── js/main.js              # App logic
├── functions/                  # Azure Function (Python) — Gemini AI analysis
│   └── function_app.py
└── TERRAFORM_COMPLETE_SETUP.md # This file
```

---

## Quick Start

```bash
# 1. Navigate to terraform directory
cd terraform

# 2. Create terraform.tfvars with your VM password
echo 'admin_password = "YourSecureP@ssw0rd123!"' > terraform.tfvars

# 3. Initialize Terraform
terraform init

# 4. Preview what will be created
terraform plan

# 5. Create everything!
terraform apply

# 6. MANUAL STEP: Authorize Azure Monitor Logs connection
# Go to Azure Portal → API Connections → azuremonitorlogs → Authorize

# 7. Get your outputs
terraform output
```

---

## Phase Reference

### Phase 1: Resource Group (`main.tf`)
- **File**: `main.tf`
- **Resources**: `azurerm_resource_group.main`
- **Concepts**: Providers, resources, variables

### Phase 2: Storage Account (`storage.tf`)
- **File**: `storage.tf`
- **Resources**: `azurerm_storage_account.storage`, `azurerm_storage_container.public_data`
- **Concepts**: Resource references, implicit dependencies

### Phase 3: Log Analytics (`log_analytics.tf`)
- **File**: `log_analytics.tf`
- **Resources**: `azurerm_log_analytics_workspace.logs`
- **Concepts**: Sensitive outputs, SKU configuration

### Phase 4: Networking (`network.tf`)
- **File**: `network.tf`
- **Resources**: VNet, Subnet, Public IP, NSG, NIC, NSG Association
- **Concepts**: CIDR notation, security rules

### Phase 5: Virtual Machine (`vm.tf`)
- **File**: `vm.tf`
- **Resources**: Windows VM, Firewall Extension, AMA Extension, DCR, DCR Association
- **Concepts**: Sensitive variables, VM extensions, Data Collection Rules

### Phase 6: Logic App (`logic_app.tf`)
- **File**: `logic_app.tf`
- **Resources**: Logic App, API Connections, Trigger, Actions, Role Assignments
- **Concepts**: Managed Identity, API connections, workflow actions

### Phase 7: Static Web App (`static_web_app.tf`)
- **File**: `static_web_app.tf`
- **Resources**: `azurerm_static_web_app.frontend`
- **Concepts**: GitHub integration, deployment tokens

### Phase 8: AI Analysis Function (`function.tf`)
- **File**: `function.tf`
- **Resources**: `azurerm_service_plan.functions`, `azurerm_storage_account.functions`, `azurerm_linux_function_app.analysis`, `azurerm_role_assignment.function_table_contributor`
- **Concepts**: Consumption plan, managed identity + RBAC for Table Storage, app settings (`GEMINI_API_KEY`, `ALLOWED_ORIGIN`, `RATE_LIMIT_FAIL_OPEN`)
- **Note**: The function *code* is deployed separately (`func azure functionapp publish`), not by Terraform.

---

## Post-Deployment Steps

After running `terraform apply`, complete these manual steps:

### 1. Authorize Azure Monitor Logs Connection (Required!)
The Azure Monitor Logs connector requires OAuth sign-in:
1. Go to **Azure Portal** → **API Connections** → `azuremonitorlogs`
2. Click **Edit API connection**
3. Click **Authorize** and sign in
4. Click **Save**

### 2. Enable Logic App (if not running)
1. Go to **Logic Apps** → `DataParser`
2. Click **Enable** if disabled
3. Click **Run Trigger** → **Recurrence** to test

### 3. Configure GitHub for Static Web App
1. Get deployment token: `terraform output -raw static_web_app_api_key`
2. Add as GitHub secret: `AZURE_STATIC_WEB_APPS_API_TOKEN_ORANGE_WAVE_0061ED81E` (must match the name referenced in the workflow file)
3. Push to trigger deployment

---

## Command Reference

```bash
# Initialize (download providers)
terraform init

# Preview changes (safe, no changes made)
terraform plan

# Apply changes (creates/updates resources)
terraform apply

# Apply without prompting
terraform apply -auto-approve

# Destroy everything
terraform destroy

# Format code
terraform fmt

# Validate syntax
terraform validate

# Show outputs
terraform output

# Show specific output
terraform output static_web_app_url

# Show sensitive output
terraform output -raw static_web_app_api_key
```

---

## Key Concepts

### Resource Naming Convention
We use descriptive local names for clarity:
- `azurerm_resource_group.main` → The main resource group
- `azurerm_storage_account.storage` → The storage account
- `azurerm_log_analytics_workspace.logs` → The log analytics workspace

### How References Work
```hcl
# Resources reference each other by TYPE.LOCAL_NAME.PROPERTY
resource_group_name = azurerm_resource_group.main.name
#                     ├── TYPE ───────────────┘    │
#                     ├── LOCAL NAME ──────────────┘
#                     └── PROPERTY
```

### Sensitive Data
- `terraform.tfvars` - Contains VM password (gitignored!)
- `*.tfstate` - Contains all resource data including secrets (gitignored!)
- Sensitive outputs use `sensitive = true` to hide in console

### Azure Monitor Agent (AMA) vs MMA
We use the modern **Azure Monitor Agent (AMA)** with **Data Collection Rules (DCR)**:
- ✅ AMA is the current, supported agent
- ❌ MMA (Microsoft Monitoring Agent) was deprecated August 2024

### Dependencies
- **Implicit**: Terraform figures out order from references
- **Explicit**: Use `depends_on` when order matters but there's no reference

---

## Files Summary

| File | Lines | Purpose |
|------|-------|---------|
| `providers.tf` | ~40 | Terraform & Azure provider configuration |
| `variables.tf` | ~120 | All input variables with defaults |
| `outputs.tf` | ~155 | All output values organized by phase |
| `main.tf` | ~25 | Resource Group |
| `storage.tf` | ~50 | Storage Account & Container |
| `log_analytics.tf` | ~40 | Log Analytics Workspace |
| `network.tf` | ~160 | All networking resources |
| `vm.tf` | ~150 | VM, extensions, DCR |
| `logic_app.tf` | ~305 | Logic App with full workflow |
| `static_web_app.tf` | ~50 | Static Web App |

---

## Troubleshooting

### "Storage account name already exists"
Storage account names must be globally unique. Change `storage_account_name` in `variables.tf`.

### "VM password doesn't meet complexity requirements"
Password must have: 14+ chars, uppercase, lowercase, number, special character (the Terraform `admin_password` variable enforces a 14-character minimum).

### Logic App not running
1. Check the Azure Monitor Logs connection is authorized
2. Verify the Logic App is enabled
3. Check the VM is sending logs (wait 10-15 minutes after VM creation)

### No attack data showing
1. Wait for real attacks (usually within hours of exposing RDP)
2. Check Log Analytics for SecurityEvent data
3. Verify the KQL query works in Log Analytics portal

---

## Next Steps

1. ✅ Run `terraform apply` to create infrastructure
2. ✅ Authorize the Azure Monitor Logs connection
3. ✅ Update GitHub Actions secret for Static Web App
4. ⏳ Wait for attacks to accumulate
5. 🎉 Watch your threat map light up!
