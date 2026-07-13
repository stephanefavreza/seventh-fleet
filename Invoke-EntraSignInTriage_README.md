# Invoke-EntraSignInTriage.ps1

> A PowerShell triage tool for investigating Entra ID (Azure AD) sign-in issues. It pulls sign-in logs, decodes error codes, detects anomalies, and produces both a visual HTML dashboard and a color-coded console summary.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

---

## Features

| Capability | Description |
|---|---|
| **Sign-In Log Retrieval** | Pulls logs via Microsoft Graph API with automatic paging |
| **AADSTS Error Decoder** | Translates 90+ error codes into plain-language meanings with remediation steps |
| **Anomaly Detection** | 6 detectors: impossible travel, burst logins, geo-anomalies, device/OS shifts, unusual hours, MFA failures |
| **HTML Dashboard** | Self-contained dark-themed report with interactive charts (Chart.js), filterable tables, and severity-coded anomaly display |
| **Console Summary** | Color-coded triage output with health indicator, top errors, remediation hints, and risk detections |

---

## Prerequisites

- **PowerShell 7+** (recommended) or Windows PowerShell 5.1
- **Microsoft.Graph.Authentication** module

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

- **Permissions** (delegated or app):
  - `AuditLog.Read.All`
  - `Directory.Read.All`

---

## Usage

```powershell
# Investigate a specific user (last 72 hours by default)
.\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "user@contoso.com"

# Investigate with a custom time window
.\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "user@contoso.com" -HoursBack 48

# Investigate a specific application
.\Invoke-EntraSignInTriage.ps1 -AppId "00000000-0000-0000-0000-000000000000"

# Investigate by application display name
.\Invoke-EntraSignInTriage.ps1 -AppDisplayName "Microsoft Teams"

# Combine filters and increase record limit
.\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "user@contoso.com" -AppDisplayName "Outlook" -Top 1000

# Save report to a specific directory
.\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "user@contoso.com" -OutputPath "C:\Reports"
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-UserPrincipalName` | String | — | UPN of the user to investigate |
| `-AppId` | String | — | Application (client) ID to filter on |
| `-AppDisplayName` | String | — | Application display name to filter on |
| `-HoursBack` | Int | 72 | How far back to pull logs (1–720 hours) |
| `-OutputPath` | String | Script directory | Where to save the HTML report |
| `-Top` | Int | 500 | Maximum sign-in records to retrieve (1–5000) |

At least one of `-UserPrincipalName`, `-AppId`, or `-AppDisplayName` is required.

---

## Anomaly Detectors

### 1. Impossible Travel
Calculates geographic distance (Haversine formula) between consecutive sign-ins. Flags when implied travel speed exceeds 900 km/h.

### 2. Burst Logins
Detects 10+ sign-in attempts within a 5-minute window — indicative of credential stuffing or brute-force attacks.

### 3. Geo-Anomaly
Identifies sign-ins from countries other than the user's most frequent ("home") country.

### 4. Device/OS Shift
Flags users authenticating from more than 2 different operating systems or 4+ different browsers within the time window.

### 5. Unusual Hours
Detects repeated sign-ins during off-hours (22:00–05:00 UTC) with a threshold of 3+ events.

### 6. MFA Failures
Groups MFA-related errors (AADSTS 50072, 50074, 50076, 50078, 50079, 500121, 53000) by user with severity scaling based on frequency.

---

## Output

### HTML Dashboard
A self-contained `.html` file saved to the output directory with the naming format:
```
SignInTriage_yyyyMMdd_HHmmss.html
```

The dashboard includes:
- Summary stat cards (success, failure, anomalies, unique users/apps/IPs)
- 6 interactive charts (timeline, success/failure ratio, top errors, countries, apps, conditional access)
- Anomaly detection results table (severity-sorted)
- Error code analysis table with remediation guidance
- Filterable sign-in log table (most recent 100 events)

The report auto-opens in your default browser after generation.

### Console Summary
A boxed, color-coded triage summary printed to the terminal including:
- Health indicator (HEALTHY / WARNING / CRITICAL based on failure rate)
- Anomaly list with severity icons
- Top error codes with occurrence counts
- Recommended remediation actions
- Location summary
- Identity Protection risk detections

---

## AADSTS Error Coverage

The built-in decoder covers 90+ common error codes across these categories:

- Authentication failures (50012, 50053, 50055, 50057, 50126...)
- MFA issues (50072, 50074, 50076, 50078, 50079, 500121...)
- Conditional Access blocks (53000, 53001, 53003, 530032...)
- Application/consent errors (65001, 65004, 65005, 70001, 700016...)
- Token/session issues (70000, 70008, 70043, 50132, 50133...)
- Device compliance (50097, 50129, 50131, 530003, 700003...)
- Federation/SSO (51000, 51001, 75003, 80001, 81004...)
- Cross-tenant (220000, 500021...)

Unknown codes are flagged with a direct link to Microsoft's error lookup page.

---

## Examples

### Triage a locked-out user
```powershell
.\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "john.doe@contoso.com" -HoursBack 24
```

### Investigate an app with consent issues
```powershell
.\Invoke-EntraSignInTriage.ps1 -AppDisplayName "Custom Portal" -HoursBack 168
```

### Check for brute-force against a service account
```powershell
.\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "svc-automation@contoso.com" -Top 2000 -HoursBack 48
```

---

## Notes

- The script connects to Microsoft Graph interactively if no session exists. For automation, connect beforehand using `Connect-MgGraph` with a certificate or managed identity.
- Sign-in logs in Entra ID have a retention period of 7–30 days depending on license (P1/P2). The `-HoursBack` parameter is capped at 720 hours (30 days).
- The HTML report uses Chart.js loaded from CDN — an internet connection is needed when viewing the report for charts to render.
- All timestamps in the report and anomaly detection are in UTC.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/my-improvement`)
5. Open a Pull Request

For bug reports and feature requests, please open an issue.

---

## License

This project is licensed under the [MIT License](./LICENSE).

---

## Disclaimer

This tool is provided **"as is"** without warranty of any kind, express or implied. Use at your own risk.

- Always test in a non-production environment before relying on this tool operationally.
- The authors are not responsible for any damage, data loss, or security incidents resulting from the use of this script.
- This tool reads sign-in logs only — it does not modify any configuration or user state in your tenant.
- Ensure you have appropriate authorization before accessing audit logs in your organization.
