# Honeypot Threat Map

Real-time visualization of RDP brute-force attacks against a Windows honeypot deployed in Azure.

![Azure](https://img.shields.io/badge/Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=flat&logo=terraform&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)

## Overview

This project deploys a Windows VM as a honeypot with RDP exposed to the internet. Failed login attempts are captured via Windows Security Events, processed through Azure Logic Apps, and visualized on an interactive map.

**Live Demo**: [orange-wave-0061ed81e.6.azurestaticapps.net](https://orange-wave-0061ed81e.6.azurestaticapps.net/)

## Architecture

```
Attackers → RDP (3389) → Windows VM → Security Events → Log Analytics
                                                              ↓
                         Static Web App ← Blob Storage ← Logic App
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## Quick Start with Terraform

```bash
cd terraform
terraform init
echo 'admin_password = "YourSecureP@ssw0rd123!"' > terraform.tfvars
terraform apply
```

**Post-deployment steps required:**
1. Authorize Azure Monitor Logs API connection in Azure Portal
2. Update GitHub secret with new Static Web App API key
3. Push to trigger frontend deployment

See [terraform/README.md](terraform/README.md) for complete instructions.

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Infrastructure** | Terraform, Azure |
| **Honeypot** | Windows Server 2022 |
| **Log Collection** | Azure Monitor Agent, Data Collection Rules |
| **Data Processing** | Logic Apps, KQL |
| **Storage** | Azure Blob Storage |
| **Frontend** | HTML/CSS/JS, Leaflet.js |
| **Hosting** | Azure Static Web Apps |
| **CI/CD** | GitHub Actions |

## Features

- Real-time attack visualization on interactive world map
- Marker clustering for high-density attack regions
- Attack details: IP, geolocation, attempt count, targeted accounts
- Daily aggregated data with automatic refresh
- Responsive design for mobile and desktop

## Project Structure

```
├── README.md               # This file
├── ARCHITECTURE.md         # Technical architecture documentation
├── index.html              # Frontend application
├── .github/workflows/      # GitHub Actions for deployment
└── terraform/              # Infrastructure as Code
    ├── README.md           # Terraform-specific docs
    └── *.tf                # Terraform configuration files
```

## Security Notice

This honeypot uses intentionally permissive security settings:
- Open NSG allowing all inbound traffic
- Disabled Windows Firewall
- Exposed RDP (port 3389)

**Do not use these configurations for production workloads.**

## License

MIT
