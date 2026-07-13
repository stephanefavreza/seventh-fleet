# Daily Mail Flow Report — On-Premises Exchange

A read-only PowerShell report that summarizes 24 hours of on-premises Exchange mail flow from message tracking logs plus live transport, queue, service, and component state. Built for a hybrid Exchange 2019 / SE environment with multiple hub-transport servers.

**Read-only guarantee:** the script never changes configuration, moves mail, clears queues, or writes to Exchange. Its only write is an optional local HTML file and an optional JSON history file.

Files in this package:

| File | Purpose |
|------|---------|
| `New-DailyMailFlowReport.ps1` | The report script. |
| `Sample-MailFlowReport.html` | An example of the generated report (open in a browser). |
| `README.md` | This document. |

---

## What it reports

1. **Executive summary** — headline counts plus an overall verdict (OK / WARNING / CRITICAL).
2. **Traffic by direction** — Inbound / Outbound / Internal, as distinct messages and volume (MB).
3. **Routing by connector** — SEND/RECEIVE event counts per connector (shows internet vs EXO vs internal routing by connector name).
4. **Hourly distribution & peak hours** — a 24-hour line chart (peak and any flagged anomalies marked, exact counts on hover), peak hour, and busiest hours (informational).
5. **Spike detection** — day-over-day totals vs a rolling baseline, plus per-hour-of-day anomaly detection.
6. **Delivery failures / NDRs** — failed message count, failure rate, top status codes, sample failures.
7. **Latency** — on-prem transport transit time (avg / median / p95 / max).
8. **Transport queues** — depth, oldest message age, status, last error (point-in-time snapshot).
9. **Security & exceptions** — on-prem policy rejections (5.7.x) and transport-agent actions.
10. **Transport rules** — configured rules and a best-effort activity approximation.
11. **Service health** — `Test-ServiceHealth` per server.
12. **Component state** — any non-Active component per server (e.g. HubTransport draining).

---

## Requirements

- Run from the **Exchange Management Shell** on a hub-transport server (or an EMS-imported remote session).
- An account able to read tracking logs, queues, and server state on the target servers.
- PowerShell 4.0 or later (the script sets `#Requires -Version 4.0`).
- No external modules. Everything uses built-in Exchange cmdlets.

---

## Quick start

```powershell
# Yesterday, all hub transport servers, HTML written to .\MailFlowReports
.\New-DailyMailFlowReport.ps1

# Recommended: enable spike detection and day-over-day baseline
.\New-DailyMailFlowReport.ps1 -HistoryPath D:\Reports\mailflow-history.json

# A specific day, emailed to the ops team
.\New-DailyMailFlowReport.ps1 -Date 2026-07-12 `
    -HistoryPath D:\Reports\mailflow-history.json `
    -SendEmail -To ops@contoso.com -From exch-report@contoso.com `
    -SmtpServer mail.contoso.com

# An explicit window instead of a calendar day
.\New-DailyMailFlowReport.ps1 -Start '2026-07-12 06:00' -End '2026-07-12 18:00'
```

The report auto-discovers hub-transport servers (`Get-TransportService`) and accepted domains (`Get-AcceptedDomain`), so no server or connector names are hardcoded.

---

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Date` | yesterday | Calendar day to report (00:00–23:59:59 local). |
| `-Start` / `-End` | — | Explicit window; overrides `-Date` when both are supplied. |
| `-Servers` | all hub transport servers | Transport servers to read from. |
| `-OutputFolder` | `.\MailFlowReports` | Folder for the HTML file (created if missing). |
| `-InternalDomains` | all accepted domains | Domains treated as internal for direction classification (exact + wildcard). |
| `-SpikeThresholdPercent` | `200` | Spike sensitivity: an hour is flagged when it exceeds its own historical baseline by this % (or mean + 3σ, whichever is higher). Also drives day-over-day deltas. |
| `-SpikeFloor` | `100` | Minimum message count an hour must reach before it can be flagged (suppresses trivially quiet overnight hours). |
| `-QueueWarnCount` | `25` | Flag any queue at or above this depth. |
| `-QueueWarnAgeMinutes` | `30` | Flag any queued message older than this. |
| `-HistoryPath` | — | JSON file for day-over-day baseline and per-hour spike detection. Strongly recommended. |
| `-BaselineDays` | `7` | Number of prior days used for rolling baselines. |
| `-SendEmail` | off | Email the HTML report. |
| `-To` / `-From` / `-SmtpServer` | — | Email delivery settings (used only with `-SendEmail`). |

---

## Methodology (why the numbers mean what they mean)

**Distinct-message counting.** A single message generates many tracking events (RECEIVE, SEND, DELIVER, FAIL…), and in a DAG the same message appears on more than one server as it transits. Volume figures are therefore **deduplicated by `MessageId` across all servers**. Per-connector and per-hour breakdowns are event counts (labeled as such) because they measure load, not distinct mail.

**Direction classification.** Each distinct message is classified once, from its sender and recipient domains checked against the accepted-domain list:

- sender external → **Inbound**
- sender internal + any external recipient → **Outbound**
- sender internal + all recipients internal → **Internal**
- empty sender (`MAIL FROM: <>`, i.e. system-generated bounces/DSNs) → excluded from directional volume and reported in the NDR section instead

> **Hybrid caveat:** because most mailboxes live in Exchange Online, a message from an on-prem sender to an EXO colleague is *logically internal* (same accepted domain) but *physically* egresses toward `mail.protection.outlook.com`. Domain-based classification calls that **Internal**, which is correct organizationally. Use the **Routing by connector** section to see the physical internet-vs-EXO split by connector name.

**Latency** correlates each message's earliest RECEIVE with its DELIVER/SEND timestamp. It measures **on-prem transport transit time**, not end-to-end internet delivery.

**Spike detection.** Two independent mechanisms, both requiring `-HistoryPath`:

- *Day-over-day:* today's total volume and failure count vs the rolling mean of up to `-BaselineDays` prior days.
- *Per-hour-of-day anomalies:* each hour is compared to the baseline for **that same hour** across prior days. An hour is flagged only when it exceeds its own baseline by `-SpikeThresholdPercent` (or mean + 3σ) **and** clears `-SpikeFloor`.

  This is deliberately not "hours above the daily average." A normal business-hours curve always sits well above the flat 24-hour mean, so that naive test would flag every midday peak, every day. The per-hour baseline instead answers the useful question — *is 03:00 today far above what 03:00 normally looks like?* — which is what actually indicates a problem (a runaway loop, a notification storm, a queue release). Per-hour detection needs at least 3 prior days of history before it activates.

**Two on-prem blind spots (stated, not faked):**

- *Spam / malware:* filtering is handled upstream by Exchange Online Protection. The security section shows only on-prem transport-agent actions and 5.7.x policy rejections; it notes this explicitly when no on-prem anti-spam agents are logging. For authoritative block/quarantine figures, use EOP / Defender reporting.
- *Transport-rule hit counts:* not cleanly exposed by on-prem tracking logs. The report lists configured rules plus an AGENTINFO-based approximation and points to EXO / DLP reporting for exact counts.

**Queues** are a **point-in-time snapshot** taken when the script runs, not a 24-hour aggregate.

---

## The overall verdict

| Verdict | Raised when |
|---------|-------------|
| **CRITICAL** | A required service is not running, or a Poison queue holds messages. |
| **WARNING** | A queue trips `-QueueWarnCount` / `-QueueWarnAgeMinutes`; a component is non-Active; failure rate ≥ 5%; a per-hour or day-over-day spike is detected. |
| **OK** | None of the above. |

The verdict appears as a colored banner at the top of the report and in the console summary.

---

## Scheduling a daily run

Create a wrapper that loads the Exchange snap-in, then calls the script. Example `Run-MailFlowReport.ps1`:

```powershell
# Load Exchange cmdlets in a plain PowerShell (non-EMS) session
. "$env:ExchangeInstallPath\bin\RemoteExchange.ps1"
Connect-ExchangeServer -auto

& 'D:\Scripts\New-DailyMailFlowReport.ps1' `
    -HistoryPath 'D:\Reports\mailflow-history.json' `
    -OutputFolder 'D:\Reports' `
    -SendEmail -To 'ops@contoso.com' -From 'exch-report@contoso.com' `
    -SmtpServer 'mail.contoso.com'
```

Register it in Task Scheduler to run each morning (covering the previous day by default):

```
Program:   powershell.exe
Arguments: -NoProfile -ExecutionPolicy Bypass -File "D:\Scripts\Run-MailFlowReport.ps1"
Run as:    an account with Exchange read rights, "Run whether user is logged on or not"
```

The first few days build history; per-hour spike detection begins once 3+ days are recorded, and day-over-day figures stabilize as the baseline fills toward `-BaselineDays`.

---

## Tuning

- **Too many / too few spike alarms:** adjust `-SpikeThresholdPercent` (higher = less sensitive) and `-SpikeFloor` (higher = ignores smaller hours).
- **Queue noise:** raise `-QueueWarnCount` / `-QueueWarnAgeMinutes` if your normal steady state carries a small backlog.
- **Direction looks off:** pass `-InternalDomains` explicitly if some accepted domains should be treated as external for your reporting (or vice versa).

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `Get-MessageTrackingLog` returns little or nothing | Wrong window, or tracking logs rolled over. The script already uses `-ResultSize Unlimited`; check the date and that tracking logging is enabled. |
| Runs slowly on a busy day | Tracking events are held in memory. Narrow the window, or run per-server with `-Servers`. |
| Latency section empty | No messages in the window had both a RECEIVE and a DELIVER/SEND event to correlate (e.g. very low traffic). |
| Spike section says it needs history | Provide `-HistoryPath`; per-hour detection needs 3+ prior daily runs. |
| Security section shows the EOP note only | Expected in hybrid — on-prem has no anti-spam agents logging; filtering is upstream. |
| Email not sent | Ensure `-SendEmail` plus all of `-To`, `-From`, `-SmtpServer` are supplied and the SMTP server accepts the relay. |
| A component shows non-Active | Confirm it is intentional maintenance (e.g. HubTransport draining) before acting — the report flags it, it does not change it. |

---

## Notes on the sample

`Sample-MailFlowReport.html` was produced by the script itself against representative data: ~21,000 messages across two hub-transport servers, a realistic business-hours curve, a sub-1% NDR rate with typical status codes, a retry queue tripping the depth/age flags, and a deliberately injected 02:00 traffic burst. In the sample, that 02:00 burst is flagged as a per-hour anomaly (~16× its normal level) while the genuine 14:00 business peak — the busiest hour of the day — is correctly **not** flagged, which is the behavior the per-hour baseline is designed to produce.

---

## Disclaimer

This script is provided **"AS IS"** without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the author be liable for any claim, damages, or other liability arising from the use of this script.

- **Test first.** Always validate in a non-production environment before relying on this script operationally.
- **Read-only by design.** The script does not modify Exchange configuration, move mail, or clear queues. Its only writes are an optional local HTML report file and an optional JSON history file.
- **No support obligation.** This is a community contribution. Issues and pull requests are welcome, but response times are not guaranteed.

---

## License

This project is licensed under the [MIT License](LICENSE).
