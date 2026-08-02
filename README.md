# Where's My RDP Attacker

_(a.k.a. **Honeypot Threat Map**)_ — real-time visualization of RDP brute-force attacks against a Windows honeypot deployed in Azure.

![Azure](https://img.shields.io/badge/Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=flat&logo=terraform&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)

Built by [Jason Eissayou](https://www.eissayou.com).

## Overview

This project deploys a Windows VM as a honeypot with RDP exposed to the internet. Failed login attempts are captured via Windows Security Events, aggregated through an Azure Logic App (KQL), written to Blob Storage as daily JSON, and visualized on an interactive map. A Python Azure Function adds AI-powered trend analysis (Google Gemini) comparing any two days.

**Live demo**: [honeypot.eissayou.com](https://honeypot.eissayou.com/)

## Architecture

```
Attackers → RDP (3389) → Windows VM → Security Events → Log Analytics
                                                             ↓
                  Static Web App  ←  Blob Storage  ←  Logic App (KQL)
                        │
                        ├─ Leaflet map + country/username leaderboards
                        │     (reads attacks_YYYY-MM-DD.json)
                        └─ AI Trend Analysis  →  Azure Function (Python)  →  Gemini
                                                  (per-IP + global rate limiting
                                                   via Azure Table Storage)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Infrastructure** | Terraform, Azure |
| **Honeypot** | Windows Server 2022 |
| **Log Collection** | Azure Monitor Agent, Data Collection Rules |
| **Data Processing** | Logic Apps, KQL |
| **Storage** | Azure Blob Storage |
| **Frontend** | HTML/CSS/JS, Leaflet.js |
| **AI Analysis** | Azure Functions (Python), Google Gemini, Table Storage rate limiting |
| **Hosting** | Azure Static Web Apps |
| **CI/CD** | GitHub Actions |

## Features

- Real-time attack visualization on an interactive world map
- Marker clustering for high-density attack regions
- Attack details: IP, geolocation, attempt count, targeted usernames
- Country and most-targeted-username leaderboards
- **AI trend analysis** comparing any two days (Google Gemini), rate-limited to protect the paid quota
- Daily aggregated data with automatic refresh
- SEO-optimized, accessible, responsive design for mobile and desktop

## Project Structure

```
├── README.md                    # This file
├── ARCHITECTURE.md              # Technical architecture documentation
├── TERRAFORM_COMPLETE_SETUP.md  # Full infrastructure setup guide
├── app/                         # Static site (the published web root)
│   ├── index.html               # Markup + SEO metadata
│   ├── css/main.css             # Styles
│   ├── js/main.js               # App logic (map, leaderboards, AI panel)
│   ├── staticwebapp.config.json # Routing, CSP + security headers
│   ├── robots.txt, sitemap.xml  # SEO
│   ├── 404.html, favicon.*, og-image.png
├── functions/                   # Azure Function (Python): Gemini AI analysis + rate limiting
│   ├── function_app.py
│   └── TROUBLESHOOTING.md
├── .github/workflows/           # GitHub Actions (Azure Static Web Apps deploy)
└── terraform/                   # Infrastructure as Code (describes the architecture)
    ├── README.md                # Terraform-specific docs
    └── *.tf                     # Terraform configuration files
```

## Run locally

**Frontend** (static site — no build step):

```bash
cd app
python3 -m http.server 8080
# open http://localhost:8080
```

**Backend** (Azure Function — optional, for the AI panel):

```bash
cd functions
# create local.settings.json with GEMINI_API_KEY and AzureWebJobsStorage
func start
```

> **The AI panel does not work from `localhost` against the deployed Function.**
> The Function's CORS allowlist contains only the Static Web App origin, so a
> request from any other origin is rejected at the preflight and the browser
> reports `TypeError: Failed to fetch`. The map and leaderboards are unaffected —
> they read public blobs, which have no such restriction.
>
> This is intentional: the endpoint spends a paid Gemini quota, so no localhost
> origin is allowed by default — otherwise anyone serving a page on that port
> could call it.
>
> If you need the AI panel while developing, add your origin to the Function's
> `ALLOWED_ORIGIN` app setting **temporarily**, restart the Function, and remove
> it when you're done. Origins must match exactly, including scheme and port:
>
> ```
> ALLOWED_ORIGIN=https://honeypot.eissayou.com,https://orange-wave-0061ed81e.6.azurestaticapps.net,http://localhost:8081
> ```
>
> The same applies when moving to a custom domain — see
> [Moving to a custom domain](#moving-to-a-custom-domain).

See [functions/TROUBLESHOOTING.md](functions/TROUBLESHOOTING.md) for local-dev and deployment tips.

## Infrastructure (Terraform)

The `terraform/` directory is the Infrastructure-as-Code description of the full
environment (VM honeypot, Log Analytics, Logic App, storage, Static Web App and
the AI Function App).

```bash
cd terraform
terraform init
echo 'admin_password = "YourSecureP@ssw0rd123!"' > terraform.tfvars
terraform apply
```

**Post-deployment steps:**
1. Authorize the Azure Monitor Logs API connection in the Azure Portal
2. Update the GitHub secret with the new Static Web App API key
3. Push to `main` to trigger the frontend deployment

The static site itself deploys automatically via GitHub Actions on push to `main`. See [terraform/README.md](terraform/README.md) and [TERRAFORM_COMPLETE_SETUP.md](TERRAFORM_COMPLETE_SETUP.md) for complete instructions.

## Moving to a custom domain

Done: the site lives at **[honeypot.eissayou.com](https://honeypot.eissayou.com/)**
(an unproxied Cloudflare CNAME to the Static Web App; Azure issues the managed
certificate). The legacy `orange-wave-0061ed81e.6.azurestaticapps.net` hostname
still serves the same content with a canonical pointing at the custom domain,
and both origins remain in the Function's CORS allowlists.

Hostnames are referenced in a handful of places. Changing the site origin means
updating all of them, or SEO tags and the CSP will point at the old address:

| File | What to change |
| --- | --- |
| `app/js/main.js` | `STORAGE_ACCOUNT`, `BLOB_CONTAINER`, `AI_FUNCTION_URL` |
| `app/staticwebapp.config.json` | `connect-src` in the CSP (blob + Function hosts) |
| `app/index.html` | `canonical`, `og:url`, `og:image`, `twitter:image`, the JSON-LD `url` / `mainEntityOfPage`, and the `preconnect` hints |
| `app/sitemap.xml` | `<loc>` |
| `app/robots.txt` | `Sitemap:` |
| `functions/function_app.py` | `ALLOWED_ORIGIN` default (or set the `ALLOWED_ORIGIN` app setting instead) |

`terraform/variables.tf` also carries these values, but that config is
illustrative and is not applied — see the note in `terraform/README.md`.

## Security Notice

This honeypot uses intentionally permissive security settings:
- Open NSG allowing all inbound traffic
- Disabled Windows Firewall
- Exposed RDP (port 3389)

**Do not use these configurations for production workloads.**

## License

[MIT](LICENSE) © Jason Eissayou
