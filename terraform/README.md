# Terraform Infrastructure

Infrastructure as Code for deploying the Azure Honeypot Threat Map.

## Architecture

```
Attackers → RDP (3389) → Windows VM → Security Events → AMA → Log Analytics
                                                                    ↓
                         Static Web App ← Blob Storage ← Logic App (KQL)
```

## Prerequisites

- Terraform >= 1.0.0
- Azure CLI (authenticated via `az login`)
- Azure subscription with sufficient quota

## Deployment

### 1. Configure Variables

Create `terraform.tfvars` with your VM password:

```hcl
admin_password = "YourSecureP@ssw0rd123!"
```

### 2. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

### 3. Post-Deployment Steps

After `terraform apply` completes, you must perform these manual steps:

#### Step 3a: Authorize Azure Monitor Logs Connection

The Logic App needs OAuth authorization to query Log Analytics:

1. Go to **Azure Portal** → **API Connections**
2. Click `azuremonitorlogs`
3. Click **Edit API connection**
4. Click **Authorize** → Sign in with Azure account
5. Click **Save**

#### Step 3b: Update GitHub Secret for Static Web App

If deploying a new Static Web App, update the GitHub deployment secret:

1. Get the new API key:
   ```bash
   terraform output -raw static_web_app_api_key
   ```

2. Go to **GitHub** → **Settings** → **Secrets and variables** → **Actions**

3. Update secret `AZURE_STATIC_WEB_APPS_API_TOKEN_ORANGE_WAVE_0061ED81E` with the new key

4. Push a commit to trigger deployment:
   ```bash
   git commit --allow-empty -m "Trigger deployment"
   git push
   ```

#### Step 3c: Verify Logic App

1. Go to **Azure Portal** → **Logic Apps** → `DataParser`
2. Click **Run Trigger** → **Recurrence** to test
3. Check **Run history** for success

## File Structure

```
├── providers.tf        # Terraform and Azure provider
├── variables.tf        # Input variables
├── outputs.tf          # Output values
├── main.tf             # Resource group
├── storage.tf          # Storage account and container
├── log_analytics.tf    # Log Analytics workspace
├── network.tf          # VNet, subnet, NSG, public IP
├── vm.tf               # Windows VM, AMA, DCR
├── logic_app.tf        # Data parser workflow
└── static_web_app.tf   # Frontend hosting
```

## Outputs

After deployment, view outputs with:

```bash
terraform output
```

Key outputs:
- `public_ip_address` - Honeypot IP (attackers will target this)
- `static_web_app_url` - Frontend URL
- `rdp_connection_string` - RDP access for admin

## Destroy

To tear down all resources:

```bash
terraform destroy
```

## Security Note

This configuration creates intentionally permissive security settings for honeypot purposes. Do not use for production workloads.
