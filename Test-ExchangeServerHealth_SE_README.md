# Exchange Server Health Check Report (SE Edition)

A PowerShell script that performs comprehensive health checks on Exchange Server 2016, 2019, and Subscription Edition (SE) environments, including Database Availability Group (DAG) monitoring.

## Overview

This script is a modernized version of Paul Cunningham's original Exchange Server Health Check script, updated to support Exchange Server SE and remove deprecated/legacy functionality.

## Supported Versions

| Exchange Version | Supported |
|-----------------|-----------|
| Exchange Server SE (Subscription Edition) | Yes |
| Exchange Server 2019 | Yes |
| Exchange Server 2016 | Yes |
| Exchange Server 2013 | No (removed) |
| Exchange Server 2010 | No (removed) |
| Exchange Server 2007 | No (removed) |

## Requirements

- PowerShell 5.1 or later
- Exchange Management Shell or Exchange PowerShell snapin available
- Appropriate Exchange admin permissions (View-Only Organization Management at minimum)
- Network access to Exchange servers (WinRM/CIM for uptime checks)

## What It Checks

### Per-Server Health
- DNS resolution
- ICMP ping reachability
- Server uptime (via CIM)
- Exchange version detection (2016 / 2019 / SE)
- Service health (Client Access, Transport, Mailbox role services)
- Transport queue length (with configurable warning/high thresholds)
- Mailbox database mount status
- MAPI connectivity
- Mail flow (Test-Mailflow)

### DAG Health
- Database copy status (Mounted, Healthy, Failed, Suspended, etc.)
- Copy and replay queue lengths
- Replay lag and truncation lag detection
- Content index state
- Replication health (Test-ReplicationHealth) per DAG member

## Usage

```powershell
# Check all servers in the organization
.\Test-ExchangeServerHealth_SE.ps1

# Check a single server
.\Test-ExchangeServerHealth_SE.ps1 -Server EX-MB01

# Generate HTML report
.\Test-ExchangeServerHealth_SE.ps1 -ReportMode

# Generate report and send via email
.\Test-ExchangeServerHealth_SE.ps1 -ReportMode -SendEmail

# Only email if alerts are found
.\Test-ExchangeServerHealth_SE.ps1 -ReportMode -SendEmail -AlertsOnly

# Use a server list file
.\Test-ExchangeServerHealth_SE.ps1 -ServerList .\servers.txt

# Custom report file name with logging
.\Test-ExchangeServerHealth_SE.ps1 -ReportMode -ReportFile "C:\Reports\health.html" -Log
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-Server` | Check a single named server (skips DAG checks) |
| `-ServerList` | Path to a text file with server names, one per line (skips DAG checks) |
| `-ReportMode` | Generate an HTML report file |
| `-ReportFile` | Custom path/name for the HTML report (default: `exchangeserverhealth_SE.html`) |
| `-SendEmail` | Send the HTML report via email |
| `-AlertsOnly` | Only send email if errors or warnings were detected |
| `-Log` | Write a log file for troubleshooting |

## Configuration

Edit the following sections at the top of the script:

### Thresholds
```powershell
[int]$transportqueuehigh = 100    # Transport queue high (fail) threshold
[int]$transportqueuewarn = 80     # Transport queue warning threshold
$mapitimeout = 10                 # MAPI connectivity test timeout (seconds)
[int]$replqueuewarning = 8        # Replication queue warning threshold
```

### Email Settings
```powershell
$smtpsettings = @{
    To =  "exchangeadmins@yourdomain.com"
    From = "exchangehealth@yourdomain.com"
    Subject = "$reportemailsubject - $now"
    SmtpServer = "smtp.yourdomain.com"
}
```

### Ignore List

Create an `ignorelist.txt` file in the same directory as the script. Add server names, DAG names, or database names (one per line) that you want to exclude from checks.

```
YOURDEVSERVER01
TestDAG
DevMailboxDB01
```

## Changes from Original Script

| Area | Before | After |
|------|--------|-------|
| Exchange SE | Not detected | Detected via build number (>= 15.2.1544) |
| WMI | `Get-WmiObject` | `Get-CimInstance` (modern, PS7-compatible) |
| Unified Messaging | Checked and reported | Removed (deprecated in SE) |
| Public Folder DBs | `Get-PublicFolderDatabase` checked | Removed (not applicable since 2013+) |
| Legacy versions | 2003/2007/2010/2013 code paths | Removed entirely |
| PowerShell | `#requires -version 2` | `#requires -version 5.1` |
| Ping | `Test-Connection` | `Test-Connection -Count 1` (faster) |
| Module loading | Only E2010 snapin | Multi-method (existing cmdlets -> SnapIn -> E2010 fallback) |
| Content Index | Basic state check | Handles "Running" and "NotApplicable" as healthy |
| Service health | Reported UM role errors | Gracefully skips unknown/removed roles |
| HTML report | Basic inline styles | Improved typography (Segoe UI) and table styling |

## Output Files

| File | Description |
|------|-------------|
| `exchangeserverhealth_SE.html` | HTML report (when `-ReportMode` is used) |
| `exchangeserverhealth.log` | Log file (when `-Log` is used) |

## Scheduling

To run as a scheduled task (e.g., daily at 7:00 AM):

```powershell
# Action
Program: powershell.exe
Arguments: -ExecutionPolicy Bypass -File "C:\Scripts\Test-ExchangeServerHealth_SE.ps1" -ReportMode -SendEmail -AlertsOnly -Log
Start in: C:\Scripts
```

Run with a service account that has Exchange View-Only Organization Management permissions and local admin on the Exchange servers (for CIM uptime queries).

## License

MIT License (inherited from original work by Paul Cunningham).

## Credits

- Original script: [Paul Cunningham](https://paulcunningham.me)
- Modernization for Exchange SE
