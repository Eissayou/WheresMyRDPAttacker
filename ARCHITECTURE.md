# Azure Backend Architecture

Technical documentation for the Honeypot Threat Map data pipeline.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA COLLECTION                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Internet Attackers                                                      │
│         │                                                                │
│         │ RDP Brute Force (Port 3389)                                   │
│         ▼                                                                │
│  ┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐  │
│  │   Windows VM    │────▶│  Azure Monitor  │────▶│   Log Analytics  │  │
│  │   (Honeypot)    │     │   Agent (AMA)   │     │    Workspace     │  │
│  └─────────────────┘     └─────────────────┘     └────────┬─────────┘  │
│                                                            │            │
│                          Event ID 4625                     │            │
│                          (Failed Logins)                   │            │
│                                                            │            │
├────────────────────────────────────────────────────────────┼────────────┤
│                           DATA PROCESSING                   │            │
├────────────────────────────────────────────────────────────┼────────────┤
│                                                            │            │
│  ┌─────────────────┐     ┌─────────────────┐              │            │
│  │    Logic App    │────▶│  Blob Storage   │              │            │
│  │   (DataParser)  │     │  (public-data)  │◀─────────────┘            │
│  │                 │     │                 │   KQL Query               │
│  │  Every 30 min   │     │ attacks_*.json  │                           │
│  └─────────────────┘     └────────┬────────┘                           │
│                                   │                                     │
├───────────────────────────────────┼─────────────────────────────────────┤
│                           FRONTEND                        │             │
├───────────────────────────────────┼─────────────────────────────────────┤
│                                   │                                     │
│                                   ▼                                     │
│                        ┌─────────────────┐                             │
│                        │  Static Web App │                             │
│                        │   (Leaflet.js)  │                             │
│                        │                 │                             │
│                        │  Threat Map UI  │                             │
│                        └─────────────────┘                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### Log Analytics Workspace

Collects Windows Security Events via Azure Monitor Agent and Data Collection Rules.

**Key Table**: `SecurityEvent`  
**Key Event**: `EventID 4625` (Failed logon attempt)

### Logic App (DataParser)

Scheduled workflow that processes attack data every 30 minutes.

**Pipeline**:
1. **Trigger**: Recurrence (30 min interval)
2. **Query**: KQL query against Log Analytics
3. **Transform**: Parse JSON response
4. **Store**: Write to Blob Storage

### KQL Query

Aggregates failed login attempts with geolocation data:

```kql
let timeOffset = 8h;
let lookbackTimeUtc = startofday(now() - timeOffset) + timeOffset;

SecurityEvent
| where TimeGenerated >= lookbackTimeUtc
| where EventID == 4625
| where AccountType == "User"
| where IpAddress !in ("-", "::1", "127.0.0.1")
| extend GeoData = geo_info_from_ip_address(IpAddress)
| project
    TimeGenerated, IpAddress,
    Country = tostring(GeoData.country),
    State = tostring(GeoData.state),
    City = tostring(GeoData.city),
    Latitude = todouble(GeoData.latitude),
    Longitude = todouble(GeoData.longitude),
    Computer, Account
| summarize
    AttackCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetAccounts = make_set(Account, 10),
    TargetComputers = make_set(Computer, 5)
  by IpAddress, Country, State, City, Latitude, Longitude
| project
    ip = tostring(IpAddress),
    country = tostring(Country),
    state = tostring(State),
    city = tostring(City),
    lat = todouble(Latitude),
    lon = todouble(Longitude),
    attack_count = toint(AttackCount),
    first_seen = tostring(FirstSeen),
    last_seen = tostring(LastSeen),
    target_accounts = tostring(TargetAccounts),
    target_computers = tostring(TargetComputers)
| order by attack_count desc
```

**Query Features**:
- Filters to current day (PST timezone)
- Excludes localhost and system accounts
- Uses `geo_info_from_ip_address()` for geolocation
- Aggregates by attacker IP with attack counts
- Captures targeted usernames and computers

### Blob Storage

Public container hosting daily attack data files.

**Container**: `public-data`  
**Access Level**: Blob (anonymous read)  
**File Pattern**: `attacks_YYYY-MM-DD.json`

**Sample Output**:
```json
[
  {
    "ip": "192.0.2.1",
    "country": "China",
    "state": "Beijing",
    "city": "Beijing",
    "lat": 39.9042,
    "lon": 116.4074,
    "attack_count": 1247,
    "first_seen": "2026-01-01T00:15:00Z",
    "last_seen": "2026-01-01T23:45:00Z",
    "target_accounts": "[\"administrator\",\"admin\",\"user\"]",
    "target_computers": "[\"HoneyVM\"]"
  }
]
```

### Static Web App

Frontend visualization using Leaflet.js with marker clustering.

**Tech Stack**: HTML, CSS, JavaScript, Leaflet.js  
**Deployment**: GitHub Actions → Azure Static Web Apps

## API Connections

| Connection | Auth Type | Purpose |
|------------|-----------|---------|
| Azure Monitor Logs | OAuth | Query Log Analytics |
| Azure Blob Storage | Access Key | Write attack data |

**Note**: Azure Monitor Logs connection requires manual OAuth authorization after deployment.

## Timezone Handling

- **Log Analytics**: Stores timestamps in UTC
- **Logic App Trigger**: Uses Pacific Standard Time
- **File Naming**: Based on PST date (`attacks_2026-01-01.json`)
- **Frontend**: Displays times in user's local timezone

## Infrastructure as Code

See `/terraform` directory for complete Terraform configuration to deploy this infrastructure.
