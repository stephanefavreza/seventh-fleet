#Requires -Version 4.0
<#
.SYNOPSIS
    Generates a daily mail flow health report for an on-premises Exchange organization
    by analyzing message tracking logs and live transport / service state.

    READ-ONLY. This script never changes configuration, moves mail, or clears queues.
    It only reads tracking logs, queues, service health, component state and transport config.

.DESCRIPTION
    Built for a hybrid Exchange 2019 / SE environment with multiple hub transport servers.

    Sections produced:
      1.  Executive summary + overall health verdict (OK / WARNING / CRITICAL)
      2.  Total volume (distinct messages, deduplicated by MessageId across all servers)
      3.  Traffic by direction (Inbound / Outbound / Internal) using accepted domains
      4.  Per-connector breakdown (maps to your named connectors -> internet vs EXO vs internal)
      5.  Hourly distribution and peak hours (informational)
      6.  Spike detection: day-over-day totals + per-hour-of-day anomalies vs history
      7.  Delivery failures / NDRs: counts, failure rate, top status codes, samples
      8.  Latency (on-prem transport transit time): avg / median / p95 / max
      9.  Transport queues: depth, oldest message age, status, last error (point-in-time)
      10. Security / exceptions: on-prem agent (spam/malware) actions + policy rejections
      11. Transport rules: configured rules + best-effort activity approximation
      12. Service health (Test-ServiceHealth) and component state (Get-ServerComponentState)

    METHODOLOGY NOTES (important):
      - Volume is counted as DISTINCT MessageId, deduplicated across all transport servers,
        so the DAG transit of a message across P01/P02 is not double counted.
      - Direction is a LOGICAL classification by accepted domain. In hybrid, on-prem -> EXO
        mail counts as Internal (same org), even though it physically egresses to
        mail.protection.outlook.com. The per-connector section shows the physical routing.
      - Latency measures on-prem transport transit only, not end-to-end delivery.
      - Spam/malware filtering is largely handled by EOP upstream; on-prem figures reflect
        only local transport agents and 5.7.x policy rejections seen in tracking logs.
      - Per-transport-rule hit counts are approximate; tracking logs do not expose them
        cleanly on-prem. Use EXO / DLP reporting for authoritative rule hit counts.
      - Queue figures are a POINT-IN-TIME snapshot taken when the script runs.

.PARAMETER Date
    Calendar day to report on (local time), covering 00:00:00 to 23:59:59.999 of that day.
    Defaults to yesterday, which is the usual target for a "daily" report run each morning.

.PARAMETER Start
.PARAMETER End
    Explicit window override. If both are supplied they take precedence over -Date.

.PARAMETER Servers
    Transport servers to pull tracking logs / queues from. Defaults to all Hub Transport
    servers discovered via Get-TransportService.

.PARAMETER OutputFolder
    Folder for the generated HTML report. Created if missing. Defaults to .\MailFlowReports.

.PARAMETER InternalDomains
    Domains treated as internal for direction classification. Defaults to every accepted
    domain from Get-AcceptedDomain (exact + wildcard supported).

.PARAMETER SpikeThresholdPercent
    Sensitivity for spike detection. An hour is flagged as a spike when today's count for
    that hour exceeds its historical baseline for the SAME hour-of-day by this percentage
    (or by mean + 3*stddev, whichever is higher). Requires -HistoryPath with >=3 prior days.
    Also used for day-over-day total/failure deltas. Default 200 (i.e. >=100% / 2x normal).

.PARAMETER SpikeFloor
    Minimum message count an hour must reach before it can be flagged as a spike. Prevents
    trivially-quiet hours (e.g. 2 -> 8 overnight) from raising alarms. Default 100.

.PARAMETER QueueWarnCount
    Flag any queue whose MessageCount is at or above this value. Default 25.

.PARAMETER QueueWarnAgeMinutes
    Flag any queued message older than this. Default 30.

.PARAMETER HistoryPath
    Optional JSON file used for day-over-day baseline / spike detection. If supplied, the
    script reads prior daily summaries, compares today to the rolling mean, and appends
    today's summary for future runs.

.PARAMETER BaselineDays
    Number of prior days used for the day-over-day rolling baseline. Default 7.

.PARAMETER SendEmail
    Switch. If set, emails the HTML report.

.PARAMETER To / From / SmtpServer
    Email delivery settings (used only with -SendEmail).

.EXAMPLE
    .\New-DailyMailFlowReport.ps1
    Reports on yesterday, all hub transport servers, writes HTML to .\MailFlowReports.

.EXAMPLE
    .\New-DailyMailFlowReport.ps1 -Date 2026-07-12 -HistoryPath D:\Reports\mailflow-history.json

.EXAMPLE
    .\New-DailyMailFlowReport.ps1 -SendEmail -To ops@contoso.com -From exch-report@contoso.com -SmtpServer mail.contoso.com

.NOTES
    Author:  Stephane Favre
    License: MIT (see LICENSE file)

    Run from the Exchange Management Shell (or an EMS-imported remote session) with an account
    that can read tracking logs, queues and server state on the target servers.
    For very high volume, narrow the window or run per-server; Get-MessageTrackingLog is pulled
    with -ResultSize Unlimited and held in memory.

    DISCLAIMER
    This script is provided "AS IS" without warranty of any kind, express or implied,
    including but not limited to the warranties of merchantability, fitness for a
    particular purpose, and noninfringement. In no event shall the author be liable for
    any claim, damages, or other liability arising from the use of this script.
    Use at your own risk. Always test in a non-production environment first.
#>

[CmdletBinding()]
param(
    [datetime]$Date = (Get-Date).Date.AddDays(-1),
    [datetime]$Start,
    [datetime]$End,
    [string[]]$Servers,
    [string]$OutputFolder = (Join-Path (Get-Location) 'MailFlowReports'),
    [string[]]$InternalDomains,
    [int]$SpikeThresholdPercent = 200,
    [int]$SpikeFloor = 100,
    [int]$QueueWarnCount = 25,
    [int]$QueueWarnAgeMinutes = 30,
    [string]$HistoryPath,
    [int]$BaselineDays = 7,
    [switch]$SendEmail,
    [string]$To,
    [string]$From,
    [string]$SmtpServer
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ------------------------------------------------------------------ helpers ---

function Write-Step { param([string]$Message) Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Message) -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Host ("[{0:HH:mm:ss}] WARN: {1}" -f (Get-Date), $Message) -ForegroundColor Yellow }

function Get-DomainFromAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    $at = $Address.LastIndexOf('@')
    if ($at -lt 0) { return $null }
    return $Address.Substring($at + 1).Trim().ToLowerInvariant()
}

function Test-InternalDomain {
    param([string]$Domain, [hashtable]$ExactSet, [string[]]$WildcardSuffixes)
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }
    $d = $Domain.ToLowerInvariant()
    if ($ExactSet.ContainsKey($d)) { return $true }
    foreach ($suffix in $WildcardSuffixes) {
        if ($d.EndsWith($suffix)) { return $true }
    }
    return $false
}

function Get-Percentile {
    param([double[]]$Values, [double]$Percentile)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    $rank = [math]::Ceiling(($Percentile / 100.0) * $sorted.Count) - 1
    if ($rank -lt 0) { $rank = 0 }
    if ($rank -ge $sorted.Count) { $rank = $sorted.Count - 1 }
    return $sorted[$rank]
}

function HtmlEncode { param([string]$Text) if ($null -eq $Text) { return '' } [System.Web.HttpUtility]::HtmlEncode($Text) }

function Get-StatusCodeMeaning {
    param([string]$Code)
    $map = @{
        '4.2.2'  = 'Recipient mailbox full (temporary)'
        '4.3.1'  = 'Insufficient system resources / low disk on server'
        '4.3.2'  = 'System not currently accepting messages'
        '4.4.1'  = 'No answer from next hop / connection timed out'
        '4.4.2'  = 'Connection dropped during transmission'
        '4.4.7'  = 'Message expired in queue (retry window exceeded)'
        '4.7.500'= 'Throttled / rate limited by the receiving system'
        '5.0.0'  = 'Generic permanent failure'
        '5.1.0'  = 'Sender address problem'
        '5.1.1'  = 'Recipient does not exist / bad mailbox address'
        '5.1.2'  = 'Invalid or unknown recipient domain'
        '5.1.3'  = 'Invalid recipient address syntax'
        '5.1.4'  = 'Ambiguous recipient (matches more than one)'
        '5.1.6'  = 'Recipient mailbox has moved'
        '5.1.7'  = 'Invalid sender address'
        '5.1.8'  = 'Invalid sender domain'
        '5.1.10' = 'Recipient not found (no such user)'
        '5.2.0'  = 'Mailbox problem'
        '5.2.1'  = 'Mailbox disabled / not accepting mail'
        '5.2.2'  = 'Recipient mailbox full / over quota'
        '5.2.3'  = 'Message too large for the recipient mailbox'
        '5.3.4'  = 'Message too big for the system'
        '5.4.0'  = 'DNS / routing error'
        '5.4.1'  = 'No route to host / relay access denied'
        '5.4.4'  = 'Unable to route; DNS lookup failed'
        '5.4.6'  = 'Routing loop detected'
        '5.4.7'  = 'Delivery time expired'
        '5.5.2'  = 'SMTP protocol / syntax error'
        '5.5.3'  = 'Too many recipients'
        '5.6.0'  = 'Message content / media error'
        '5.7.0'  = 'Access denied (authentication or policy)'
        '5.7.1'  = 'Delivery not authorized; blocked by policy or relay denied'
        '5.7.5'  = 'Cryptographic failure (TLS / encryption)'
        '5.7.13' = 'Sender account disabled'
        '5.7.23' = 'SPF validation failed for the sender domain'
        '5.7.26' = 'Failed authentication (DMARC / SPF / DKIM)'
        '5.7.64' = 'Relay not permitted for this connector'
        '5.7.133'= 'Sender not allowed to send to this recipient'
        '5.7.501'= 'Access denied; spoofing or blocked sender (EOP)'
        '5.7.509'= 'Message failed authentication (unauthenticated)'
        '5.7.606'= 'Blocked by connection filter (sender IP on a block list)'
        '5.7.708'= 'Access denied; traffic blocked by Exchange Online Protection'
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    switch -regex ($Code) {
        '^2\.'  { return 'Success / delivered' }
        '^4\.'  { return 'Temporary failure (sender will retry)' }
        '^5\.'  { return 'Permanent failure' }
        default { return 'No status code parsed from log' }
    }
}

# ------------------------------------------------------------- window setup ---

if ($PSBoundParameters.ContainsKey('Start') -and $PSBoundParameters.ContainsKey('End')) {
    $windowStart = $Start
    $windowEnd   = $End
    $windowLabel = ("{0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}" -f $windowStart, $windowEnd)
} else {
    $windowStart = $Date.Date
    $windowEnd   = $Date.Date.AddDays(1).AddMilliseconds(-1)
    $windowLabel = ("{0:yyyy-MM-dd}" -f $Date)
}

Write-Step "Reporting window: $windowLabel"

# HttpUtility for HTML encoding
try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch { }

# ------------------------------------------------ discover transport servers ---

if (-not $Servers -or $Servers.Count -eq 0) {
    Write-Step "Discovering hub transport servers via Get-TransportService..."
    $Servers = @(Get-TransportService | Select-Object -ExpandProperty Name)
}
if (-not $Servers -or $Servers.Count -eq 0) {
    throw "No transport servers found or specified. Use -Servers to specify them explicitly."
}
Write-Step ("Transport servers: {0}" -f ($Servers -join ', '))

# -------------------------------------------------- accepted / internal set ---

if (-not $InternalDomains -or $InternalDomains.Count -eq 0) {
    Write-Step "Loading accepted domains for direction classification..."
    $InternalDomains = @(Get-AcceptedDomain | Select-Object -ExpandProperty DomainName |
                         ForEach-Object { $_.ToString() })
}

$exactInternal = @{}
$wildcardInternal = New-Object System.Collections.Generic.List[string]
foreach ($dom in $InternalDomains) {
    $d = $dom.ToLowerInvariant().Trim()
    if ($d.StartsWith('*.')) {
        $wildcardInternal.Add($d.Substring(1))   # "*.foo.com" -> ".foo.com"
    } elseif ($d -eq '*') {
        # a bare "*" accepted domain would make everything internal; ignore for classification
    } else {
        if (-not $exactInternal.ContainsKey($d)) { $exactInternal[$d] = $true }
    }
}
Write-Step ("Internal domains: {0} exact, {1} wildcard" -f $exactInternal.Count, $wildcardInternal.Count)

# ---------------------------------------------------- pull tracking events ---

$fields = 'EventId','Source','Sender','Recipients','RecipientStatus','RecipientCount',
          'MessageId','InternalMessageId','Timestamp','TotalBytes','ConnectorId',
          'ServerHostname','MessageSubject','SourceContext'

Write-Step "Collecting message tracking logs (this can take a while on busy servers)..."
$events = New-Object System.Collections.Generic.List[object]
foreach ($srv in $Servers) {
    Write-Step "  -> $srv"
    try {
        Get-MessageTrackingLog -Server $srv -Start $windowStart -End $windowEnd -ResultSize Unlimited |
            Select-Object $fields |
            ForEach-Object { $events.Add($_) }
    } catch {
        Write-Warn "Failed to read tracking log from $srv : $($_.Exception.Message)"
    }
}
Write-Step ("Collected {0} tracking events." -f $events.Count)

# --------------------------------------------- group by message + classify ---

Write-Step "Grouping events by message and classifying direction..."

# Key each message. Prefer MessageId; fall back to InternalMessageId when absent.
$byMessage = @{}
foreach ($e in $events) {
    $key = $e.MessageId
    if ([string]::IsNullOrWhiteSpace($key)) { $key = "INT:$($e.InternalMessageId)" }
    if ([string]::IsNullOrWhiteSpace($key)) { continue }
    if (-not $byMessage.ContainsKey($key)) {
        $byMessage[$key] = New-Object System.Collections.Generic.List[object]
    }
    $byMessage[$key].Add($e)
}

$inbound = 0; $outbound = 0; $internal = 0; $unclassified = 0
$inBytes = [long]0; $outBytes = [long]0; $intBytes = [long]0
$hourCounts = New-Object 'int[]' 24
$latencies = New-Object System.Collections.Generic.List[double]

foreach ($key in $byMessage.Keys) {
    $grp = $byMessage[$key]

    # sender: first non-empty Sender across events
    $sender = $null
    foreach ($ev in $grp) { if (-not [string]::IsNullOrWhiteSpace($ev.Sender)) { $sender = $ev.Sender; break } }

    # recipients: union across the group
    $recips = New-Object System.Collections.Generic.HashSet[string]
    foreach ($ev in $grp) {
        if ($ev.Recipients) {
            foreach ($r in $ev.Recipients) {
                if (-not [string]::IsNullOrWhiteSpace($r)) { [void]$recips.Add($r.ToLowerInvariant()) }
            }
        }
    }

    $senderDom = Get-DomainFromAddress $sender
    $senderInternal = Test-InternalDomain $senderDom $exactInternal $wildcardInternal

    $anyExternalRecip = $false; $anyRecip = $false
    foreach ($r in $recips) {
        $anyRecip = $true
        $rd = Get-DomainFromAddress $r
        if (-not (Test-InternalDomain $rd $exactInternal $wildcardInternal)) { $anyExternalRecip = $true }
    }

    # message size: max TotalBytes seen in the group
    $size = [long]0
    foreach ($ev in $grp) { if ($ev.TotalBytes -and [long]$ev.TotalBytes -gt $size) { $size = [long]$ev.TotalBytes } }

    if ([string]::IsNullOrWhiteSpace($senderDom)) {
        # empty MAIL FROM (<>) => system-generated message (DSN/bounce/notification).
        # These are reported in the NDR/DSN section; keep them out of directional volume.
        $unclassified++
    } elseif (-not $senderInternal) {
        $inbound++;  $inBytes += $size
    } elseif ($anyExternalRecip) {
        $outbound++; $outBytes += $size
    } elseif ($anyRecip) {
        $internal++; $intBytes += $size
    } else {
        $unclassified++
    }

    # hourly bucket by earliest timestamp
    $earliest = ($grp | Sort-Object Timestamp | Select-Object -First 1).Timestamp
    if ($earliest) { $hourCounts[[int]$earliest.Hour]++ }

    # latency: earliest RECEIVE/SUBMIT -> latest DELIVER/SEND
    $recvEvents = $grp | Where-Object { $_.EventId -in @('RECEIVE','SUBMIT') } | Sort-Object Timestamp
    $doneEvents = $grp | Where-Object { $_.EventId -in @('DELIVER','SEND') }    | Sort-Object Timestamp
    if ($recvEvents -and $doneEvents) {
        $t0 = ($recvEvents | Select-Object -First 1).Timestamp
        $t1 = ($doneEvents | Select-Object -Last 1).Timestamp
        if ($t0 -and $t1) {
            $sec = ($t1 - $t0).TotalSeconds
            if ($sec -ge 0 -and $sec -lt 86400) { $latencies.Add($sec) }
        }
    }
}

$totalMessages = $inbound + $outbound + $internal
Write-Step ("Distinct messages: {0} (In {1} / Out {2} / Internal {3} / Unclassified {4})" -f `
    $totalMessages, $inbound, $outbound, $internal, $unclassified)

# --------------------------------------- per-connector (event-count) view ---

Write-Step "Building per-connector breakdown..."
$connectorRows =
    $events |
    Where-Object { $_.EventId -in @('SEND','RECEIVE') -and -not [string]::IsNullOrWhiteSpace($_.ConnectorId) } |
    Group-Object ConnectorId |
    Sort-Object Count -Descending |
    Select-Object @{n='Connector';e={$_.Name}}, @{n='Events';e={$_.Count}}

# ------------------------------------------- peak hours (informational) ---
# Peak hour and busiest hours are reported for context only, NOT as alarms.
# A normal business-hours curve always sits well above the flat 24h mean, so
# flagging "hours above 2x the daily average" produces a false alarm every day.
# Genuine "sudden spike" detection needs a per-hour-of-day baseline from history
# (is 03:00 today far above the usual 03:00?) - see the history block below,
# which populates $hourSpikes when enough historical days are available.

$activeHours = @($hourCounts | Where-Object { $_ -gt 0 }).Count
$hourlyMean  = if ($activeHours -gt 0) { [double]$totalMessages / 24.0 } else { 0 }
$peakHour    = 0; $peakVal = 0
for ($h = 0; $h -lt 24; $h++) { if ($hourCounts[$h] -gt $peakVal) { $peakVal = $hourCounts[$h]; $peakHour = $h } }

# top 3 busiest hours, informational
$busiestHours = @(
    0..23 | ForEach-Object { [pscustomobject]@{ H = $_; Count = $hourCounts[$_] } } |
    Where-Object { $_.Count -gt 0 } | Sort-Object Count -Descending | Select-Object -First 3
)

# populated later from historical per-hour baseline (empty until then)
$hourSpikes = New-Object System.Collections.Generic.List[object]

# ------------------------------------------------ delivery failures / NDRs ---

Write-Step "Analyzing delivery failures and NDRs..."
$failEvents = @($events | Where-Object { $_.EventId -eq 'FAIL' })
$dsnEvents  = @($events | Where-Object { $_.EventId -eq 'DSN'  })
$dsnCount   = $dsnEvents.Count

# distinct failed messages
$failedMsgIds = New-Object System.Collections.Generic.HashSet[string]
foreach ($f in $failEvents) {
    $k = if ([string]::IsNullOrWhiteSpace($f.MessageId)) { "INT:$($f.InternalMessageId)" } else { $f.MessageId }
    if (-not [string]::IsNullOrWhiteSpace($k)) { [void]$failedMsgIds.Add($k) }
}
$failedCount = $failedMsgIds.Count
$failureRate = if ($totalMessages -gt 0) { [math]::Round(100.0 * $failedCount / $totalMessages, 2) } else { 0 }

# top status codes: parse enhanced code (n.n.n) from RecipientStatus / SourceContext
$statusRegex = [regex]'\b([245]\.\d{1,3}\.\d{1,3})\b'
$codeTally = @{}
$failSamples = New-Object System.Collections.Generic.List[object]
foreach ($f in $failEvents) {
    $text = ''
    if ($f.RecipientStatus) { $text += ($f.RecipientStatus -join ' ') }
    if ($f.SourceContext)   { $text += ' ' + $f.SourceContext }
    $m = $statusRegex.Match($text)
    $code = if ($m.Success) { $m.Groups[1].Value } else { 'unknown' }
    if (-not $codeTally.ContainsKey($code)) { $codeTally[$code] = 0 }
    $codeTally[$code]++
    if ($failSamples.Count -lt 15) {
        $failSamples.Add([pscustomobject]@{
            Time    = $f.Timestamp
            Sender  = $f.Sender
            Recipient = if ($f.Recipients) { ($f.Recipients -join '; ') } else { '' }
            Code    = $code
            Subject = $f.MessageSubject
        })
    }
}
$topCodes = $codeTally.GetEnumerator() | Sort-Object Value -Descending |
            Select-Object @{n='StatusCode';e={$_.Key}}, @{n='Count';e={$_.Value}} -First 10

# --------------------------------------------------------------- latency ---

$latAvg = if ($latencies.Count) { [math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { $null }
$latMed = if ($latencies.Count) { [math]::Round((Get-Percentile $latencies.ToArray() 50), 2) } else { $null }
$latP95 = if ($latencies.Count) { [math]::Round((Get-Percentile $latencies.ToArray() 95), 2) } else { $null }
$latMax = if ($latencies.Count) { [math]::Round(($latencies | Measure-Object -Maximum).Maximum, 2) } else { $null }

# ------------------------------------------------------ queues (snapshot) ---

Write-Step "Snapshotting transport queues..."
$queueRows = New-Object System.Collections.Generic.List[object]
$queueAlert = $false
foreach ($srv in $Servers) {
    try {
        $queues = Get-Queue -Server $srv -ErrorAction Stop |
                  Where-Object { $_.Identity -notlike '*\Shadow\*' }
    } catch {
        Write-Warn "Get-Queue failed on $srv : $($_.Exception.Message)"
        continue
    }
    foreach ($q in $queues) {
        $count = [int]$q.MessageCount
        $isSystemQ = ($q.DeliveryType -in @('Undefined','ShadowRedundancy')) -and $count -eq 0
        if ($count -eq 0 -and $q.Identity -notlike '*\Poison' -and $q.Identity -notlike '*\Submission' -and $q.Identity -notlike '*\Unreachable') {
            continue  # skip empty ordinary queues to keep the report readable
        }

        # oldest message age (best-effort; guarded)
        $oldestAgeMin = $null
        if ($count -gt 0) {
            try {
                $oldest = Get-Message -Queue $q.Identity -ResultSize 1 -ErrorAction Stop |
                          Sort-Object DateReceived | Select-Object -First 1
                if ($oldest -and $oldest.DateReceived) {
                    $oldestAgeMin = [math]::Round(((Get-Date) - $oldest.DateReceived).TotalMinutes, 1)
                }
            } catch { }
        }

        $flag = ''
        if ($count -ge $QueueWarnCount) { $flag = 'HIGH DEPTH'; $queueAlert = $true }
        if ($oldestAgeMin -ne $null -and $oldestAgeMin -ge $QueueWarnAgeMinutes) {
            $flag = (($flag, 'STALE') | Where-Object { $_ }) -join ' + '; $queueAlert = $true
        }
        if ($q.Identity -like '*\Poison' -and $count -gt 0) { $flag = 'POISON'; $queueAlert = $true }

        $queueRows.Add([pscustomobject]@{
            Server        = $srv
            Queue         = ($q.Identity -replace '.*\\','')
            NextHop       = $q.NextHopDomain
            DeliveryType  = $q.DeliveryType
            Status        = $q.Status
            Count         = $count
            OldestMin     = $oldestAgeMin
            LastError     = $q.LastError
            Flag          = $flag
        })
    }
}

# -------------------------------------- security / exceptions (on-prem) ---

Write-Step "Summarizing on-prem agent activity and policy rejections..."
# Policy rejections visible in tracking (5.7.x) as a proxy for on-prem block/flag
$policyRejects = 0
foreach ($f in $failEvents) {
    $text = ''
    if ($f.RecipientStatus) { $text += ($f.RecipientStatus -join ' ') }
    if ($f.SourceContext)   { $text += ' ' + $f.SourceContext }
    if ($text -match '\b5\.7\.\d{1,3}\b') { $policyRejects++ }
}

# Agent log (anti-spam / malware) - only if agents log locally on the run server
$agentSummary = @()
$agentNote = ''
try {
    $agentLog = Get-AgentLog -StartDate $windowStart -EndDate $windowEnd -ErrorAction Stop
    if ($agentLog) {
        $agentSummary = $agentLog | Group-Object Action |
                        Sort-Object Count -Descending |
                        Select-Object @{n='Action';e={$_.Name}}, @{n='Count';e={$_.Count}}
    } else {
        $agentNote = 'No on-prem agent log entries in window (filtering handled upstream by EOP).'
    }
} catch {
    $agentNote = 'On-prem anti-spam agents not present / not logging on this server. Spam and malware filtering is handled upstream by Exchange Online Protection; consult EOP / Defender reporting for authoritative block/quarantine figures.'
}

# --------------------------------------------------- transport rules ---

Write-Step "Enumerating transport rules..."
$ruleRows = @()
$ruleNote = 'Per-rule hit counts are not exposed cleanly by on-prem tracking logs. The list below is the configured rule set; for authoritative hit counts use EXO mail flow / DLP reporting or transport agent logs.'
try {
    $ruleRows = Get-TransportRule -ErrorAction Stop |
                Select-Object Name, State, Priority |
                Sort-Object Priority
} catch {
    $ruleNote = 'Get-TransportRule unavailable in this session.'
}
# best-effort: messages touched by the transport rule agent (AGENTINFO referencing rules)
$ruleAgentTouches = @($events | Where-Object {
    $_.EventId -eq 'AGENTINFO' -and (
        ($_.SourceContext -and $_.SourceContext -match 'Rule') -or
        ($_.Source -and $_.Source -match 'AGENT')
    )
}).Count

# ------------------------------------------- service + component health ---

Write-Step "Checking service health and component state..."
$serviceRows = New-Object System.Collections.Generic.List[object]
$componentRows = New-Object System.Collections.Generic.List[object]
$serviceAlert = $false
$componentAlert = $false

foreach ($srv in $Servers) {
    try {
        $health = Test-ServiceHealth -Server $srv -ErrorAction Stop
        foreach ($role in $health) {
            $notRunning = @($role.ServicesNotRunning)
            if ($notRunning.Count -gt 0) { $serviceAlert = $true }
            $serviceRows.Add([pscustomobject]@{
                Server            = $srv
                Role              = $role.Role
                RequiredRunning   = $role.RequiredServicesRunning
                ServicesNotRunning= if ($notRunning.Count) { ($notRunning -join ', ') } else { '' }
            })
        }
    } catch {
        Write-Warn "Test-ServiceHealth failed on $srv : $($_.Exception.Message)"
        $serviceRows.Add([pscustomobject]@{ Server=$srv; Role='(error)'; RequiredRunning=$false; ServicesNotRunning=$_.Exception.Message })
        $serviceAlert = $true
    }

    try {
        $comp = Get-ServerComponentState -Identity $srv -ErrorAction Stop |
                Where-Object { $_.State -ne 'Active' }
        foreach ($c in $comp) {
            $componentAlert = $true
            $componentRows.Add([pscustomobject]@{
                Server    = $srv
                Component = $c.Component
                State     = $c.State
            })
        }
    } catch {
        Write-Warn "Get-ServerComponentState failed on $srv : $($_.Exception.Message)"
    }
}

# -------------------------------------- day-over-day baseline / spike ---

$dodRows = @()
$dodAlert = $false
$todaySummary = [pscustomobject]@{
    Date       = ('{0:yyyy-MM-dd}' -f $windowStart)
    Total      = $totalMessages
    Inbound    = $inbound
    Outbound   = $outbound
    Internal   = $internal
    Failed     = $failedCount
    HourCounts = $hourCounts
}
if ($HistoryPath) {
    $history = @()
    if (Test-Path $HistoryPath) {
        try { $history = @(Get-Content $HistoryPath -Raw | ConvertFrom-Json) } catch { $history = @() }
    }
    $prior         = @($history | Select-Object -Last $BaselineDays)
    $priorTotals   = $prior | Select-Object -ExpandProperty Total   -ErrorAction SilentlyContinue
    $priorFailures = $prior | Select-Object -ExpandProperty Failed  -ErrorAction SilentlyContinue

    # --- per-hour-of-day spike detection (the real "sudden spike" test) ---
    # For each hour, build the baseline mean+stddev from prior days' HourCounts and
    # flag today's hour only if it is both well above that hour's normal level AND
    # above an absolute floor (so a quiet 03:00 going 2->8 does not alarm).
    # tolerate older history files written before HourCounts existed
    $priorHourSets = @($prior |
        Where-Object { ($_.PSObject.Properties.Name -contains 'HourCounts') -and $_.HourCounts } |
        ForEach-Object { ,@($_.HourCounts) })
    if ($priorHourSets.Count -ge 3) {
        for ($h = 0; $h -lt 24; $h++) {
            $samples = @()
            foreach ($set in $priorHourSets) { if ($set.Count -ge 24) { $samples += [double]$set[$h] } }
            if ($samples.Count -ge 3) {
                $mean = ($samples | Measure-Object -Average).Average
                $sd   = if ($samples.Count -gt 1) {
                            [math]::Sqrt((($samples | ForEach-Object { [math]::Pow($_-$mean,2) } | Measure-Object -Sum).Sum) / ($samples.Count - 1))
                        } else { 0 }
                $today = [double]$hourCounts[$h]
                $threshold = [math]::Max($mean * ($SpikeThresholdPercent / 100.0), $mean + 3 * $sd)
                if ($today -ge $SpikeFloor -and $today -gt $threshold -and $mean -gt 0) {
                    $hourSpikes.Add([pscustomobject]@{
                        Hour     = ('{0:00}:00-{0:00}:59' -f $h)
                        Count    = $hourCounts[$h]
                        Baseline = [math]::Round($mean, 0)
                        VsNormal = [math]::Round($today / [math]::Max($mean,1), 1)
                    })
                }
            }
        }
    }

    if ($priorTotals -and @($priorTotals).Count -ge 2) {
        $baseTotal = ($priorTotals | Measure-Object -Average).Average
        $baseFail  = if ($priorFailures) { ($priorFailures | Measure-Object -Average).Average } else { 0 }
        $totalDelta = if ($baseTotal -gt 0) { [math]::Round(100.0 * ($totalMessages - $baseTotal) / $baseTotal, 1) } else { 0 }
        $failDelta  = if ($baseFail -gt 0)  { [math]::Round(100.0 * ($failedCount   - $baseFail)  / $baseFail, 1) } else { 0 }
        if ([math]::Abs($totalDelta) -ge ($SpikeThresholdPercent - 100)) { $dodAlert = $true }
        if ($failDelta -ge ($SpikeThresholdPercent - 100)) { $dodAlert = $true }
        $dodRows = @(
            [pscustomobject]@{ Metric='Total volume';    Today=$totalMessages; Baseline=[math]::Round($baseTotal,0); DeltaPct=$totalDelta }
            [pscustomobject]@{ Metric='Delivery failures'; Today=$failedCount;  Baseline=[math]::Round($baseFail,0);  DeltaPct=$failDelta }
        )
    } else {
        $dodRows = @([pscustomobject]@{ Metric='(baseline)'; Today=$totalMessages; Baseline='n/a'; DeltaPct='building history' })
    }

    # append today and persist
    $history = @($history) + $todaySummary
    try {
        # ConvertTo-Json collapses a single-element array into a bare object; force a real array
        $json = ($history | ConvertTo-Json -Depth 4)
        if ($json -and -not $json.TrimStart().StartsWith('[')) { $json = "[`r`n$json`r`n]" }
        $json | Set-Content -Path $HistoryPath -Encoding UTF8
    } catch { Write-Warn "Could not write history file: $($_.Exception.Message)" }
}

# ------------------------------------------------- overall health verdict ---

$critical = ($serviceAlert) -or ($queueRows | Where-Object { $_.Flag -match 'POISON' })
$warning  = ($queueAlert) -or ($componentAlert) -or ($failureRate -ge 5) -or ($hourSpikes.Count -gt 0) -or ($dodAlert) -or ($serviceAlert)
if ($critical) { $verdict = 'CRITICAL'; $verdictColor = '#b00020' }
elseif ($warning) { $verdict = 'WARNING'; $verdictColor = '#b8860b' }
else { $verdict = 'OK'; $verdictColor = '#1a7f37' }

# ---------------------------------------------------------- build HTML ---

Write-Step "Rendering HTML report..."

$css = @'
<style>
  body { font-family: Segoe UI, Arial, sans-serif; color:#1f2328; margin:0; padding:24px; background:#f6f8fa; }
  h1 { font-size:22px; margin:0 0 4px 0; }
  h2 { font-size:16px; margin:26px 0 8px 0; border-bottom:2px solid #d0d7de; padding-bottom:4px; }
  .sub { color:#57606a; font-size:13px; margin-bottom:16px; }
  .verdict { display:inline-block; color:#fff; padding:6px 14px; border-radius:6px; font-weight:600; font-size:15px; }
  .cards { display:flex; flex-wrap:wrap; gap:12px; margin:14px 0; }
  .card { background:#fff; border:1px solid #d0d7de; border-radius:8px; padding:12px 16px; min-width:150px; }
  .card .n { font-size:24px; font-weight:700; }
  .card .l { font-size:12px; color:#57606a; text-transform:uppercase; letter-spacing:.03em; }
  table { border-collapse:collapse; width:100%; background:#fff; font-size:13px; margin-bottom:8px; }
  th, td { border:1px solid #d0d7de; padding:6px 10px; text-align:left; vertical-align:top; }
  th { background:#eaeef2; }
  tr:nth-child(even) td { background:#f6f8fa; }
  .ok { color:#1a7f37; font-weight:600; }
  .warn { color:#b8860b; font-weight:600; }
  .crit { color:#b00020; font-weight:600; }
  .note { background:#fff8e1; border:1px solid #ffe08a; border-radius:6px; padding:10px 12px; font-size:12px; color:#5c4400; margin:8px 0; }
  .bar { background:#0969da; height:14px; border-radius:3px; display:inline-block; }
  .muted { color:#57606a; font-size:12px; }
</style>
'@

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<html><head><meta charset="utf-8">' + $css + '</head><body>')
[void]$sb.AppendLine("<h1>Daily Mail Flow Report - On-Premises Exchange</h1>")
[void]$sb.AppendLine("<div class='sub'>Window: <b>$windowLabel</b> &nbsp;|&nbsp; Servers: $($Servers -join ', ') &nbsp;|&nbsp; Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</div>")
[void]$sb.AppendLine("<div class='verdict' style='background:$verdictColor'>Overall: $verdict</div>")

# summary cards
[void]$sb.AppendLine("<div class='cards'>")
foreach ($c in @(
    @{l='Total messages'; n=$totalMessages},
    @{l='Inbound';       n=$inbound},
    @{l='Outbound';      n=$outbound},
    @{l='Internal';      n=$internal},
    @{l='Failed (NDR)';  n=$failedCount},
    @{l='Failure rate';  n="$failureRate%"},
    @{l='Peak hour';     n=('{0:00}:00' -f $peakHour)}
)) {
    [void]$sb.AppendLine("<div class='card'><div class='n'>$($c.n)</div><div class='l'>$($c.l)</div></div>")
}
[void]$sb.AppendLine("</div>")

# volume + bytes
[void]$sb.AppendLine("<h2>1. Traffic by direction</h2>")
[void]$sb.AppendLine("<p class='muted'>Distinct messages, deduplicated by MessageId across all transport servers. Direction is by accepted-domain (logical); on-prem &rarr; EXO counts as Internal. See connector view for physical routing.</p>")
[void]$sb.AppendLine("<table><tr><th>Direction</th><th>Messages</th><th>Volume (MB)</th><th>Share</th></tr>")
foreach ($d in @(
    @{n='Inbound';  c=$inbound;  b=$inBytes},
    @{n='Outbound'; c=$outbound; b=$outBytes},
    @{n='Internal'; c=$internal; b=$intBytes}
)) {
    $share = if ($totalMessages -gt 0) { [math]::Round(100.0*$d.c/$totalMessages,1) } else { 0 }
    $mb = [math]::Round($d.b/1MB,1)
    $barw = [int]([math]::Min(100,$share)*2)
    [void]$sb.AppendLine("<tr><td>$($d.n)</td><td>$($d.c)</td><td>$mb</td><td><span class='bar' style='width:${barw}px'></span> $share%</td></tr>")
}
[void]$sb.AppendLine("</table>")
if ($unclassified -gt 0) { [void]$sb.AppendLine("<p class='muted'>$unclassified message(s) could not be classified (no resolvable sender/recipient domain) - typically system/DSN traffic.</p>") }

# connector breakdown
[void]$sb.AppendLine("<h2>2. Routing by connector (SEND/RECEIVE events)</h2>")
[void]$sb.AppendLine("<p class='muted'>Event counts (not distinct messages). Connector names reveal internet vs EXO vs internal routing.</p>")
[void]$sb.AppendLine("<table><tr><th>Connector</th><th>Events</th></tr>")
foreach ($r in $connectorRows) { [void]$sb.AppendLine("<tr><td>$(HtmlEncode $r.Connector)</td><td>$($r.Events)</td></tr>") }
[void]$sb.AppendLine("</table>")

# hourly distribution + peak (informational)
[void]$sb.AppendLine("<h2>3. Hourly distribution &amp; peak hours</h2>")
$busiestText = ($busiestHours | ForEach-Object { '{0:00}:00 ({1})' -f $_.H, $_.Count }) -join ', '
[void]$sb.AppendLine("<p class='muted'>Peak hour: <b>$('{0:00}:00-{0:00}:59' -f $peakHour)</b> with $peakVal messages. Busiest hours: $busiestText. Hourly mean: $([math]::Round($hourlyMean,1)). (Peaks are informational; anomaly detection is in section 4.)</p>")

# --- Outlook-compatible HTML table bar chart: messages per hour ---
# SVG is not supported by Outlook's Word-based renderer, so we use a table
# where each column is one hour with a colored bar (table cell with height).
$maxHourVal = [math]::Max(1, ($hourCounts | Measure-Object -Maximum).Maximum)
$barMaxPx = 120  # max bar height in pixels

# which hours are flagged anomalies (mark them on the chart)
$spikeIdx = @{}
foreach ($s in $hourSpikes) { $spikeIdx[[int]$s.Hour.Substring(0,2)] = $true }

$chart = New-Object System.Text.StringBuilder
[void]$chart.Append("<table border='0' cellpadding='0' cellspacing='0' style='border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;'>")

# bar row: each <td> contains a vertical bar via a nested single-cell table with height
[void]$chart.Append("<tr>")
for ($h = 0; $h -lt 24; $h++) {
    $barH = if ($hourCounts[$h] -gt 0) { [math]::Max(2, [int]([double]$hourCounts[$h] / $maxHourVal * $barMaxPx)) } else { 0 }
    $col = if ($h -eq $peakHour) { '#b00020' } elseif ($spikeIdx.ContainsKey($h)) { '#b8860b' } else { '#0969da' }
    # empty space above + colored bar below, inside a fixed-height cell
    $spaceH = $barMaxPx - $barH
    [void]$chart.Append("<td valign='bottom' align='center' style='padding:0 1px;vertical-align:bottom;'>")
    if ($barH -gt 0) {
        [void]$chart.Append("<table border='0' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'><tr><td style='background-color:$col;width:18px;height:${barH}px;font-size:1px;line-height:1px;'>&nbsp;</td></tr></table>")
    }
    [void]$chart.Append("</td>")
}
[void]$chart.Append("</tr>")

# count row: show the actual number below each bar
[void]$chart.Append("<tr>")
for ($h = 0; $h -lt 24; $h++) {
    [void]$chart.Append("<td align='center' style='padding:2px 1px 0 1px;font-size:9px;color:#57606a;'>$($hourCounts[$h])</td>")
}
[void]$chart.Append("</tr>")

# hour label row
[void]$chart.Append("<tr>")
for ($h = 0; $h -lt 24; $h++) {
    [void]$chart.Append("<td align='center' style='padding:2px 1px;font-size:9px;color:#57606a;'>$('{0:00}' -f $h)</td>")
}
[void]$chart.Append("</tr>")
[void]$chart.Append("</table>")

[void]$sb.AppendLine($chart.ToString())
[void]$sb.AppendLine("<p class='muted' style='font-size:12px;color:#57606a;'><span style='color:#0969da'>&#9632;</span> hourly volume &nbsp; <span style='color:#b00020'>&#9632;</span> peak hour &nbsp; <span style='color:#b8860b'>&#9632;</span> flagged anomaly</p>")

# spike detection (day-over-day + per-hour-of-day anomalies)
[void]$sb.AppendLine("<h2>4. Spike detection</h2>")
if ($HistoryPath) {
    [void]$sb.AppendLine("<p class='muted'>Day-over-day vs rolling mean of up to $BaselineDays prior days. Per-hour anomalies compare each hour to its own historical baseline (threshold ${SpikeThresholdPercent}% of normal or mean+3&sigma;, floor $SpikeFloor msgs).</p>")
    [void]$sb.AppendLine("<table><tr><th>Metric</th><th>Today</th><th>Baseline</th><th>Delta %</th></tr>")
    foreach ($r in $dodRows) {
        $cls = if (($r.DeltaPct -is [double]) -and [math]::Abs($r.DeltaPct) -ge ($SpikeThresholdPercent-100)) { "class='warn'" } else { '' }
        [void]$sb.AppendLine("<tr><td>$($r.Metric)</td><td>$($r.Today)</td><td>$($r.Baseline)</td><td $cls>$($r.DeltaPct)</td></tr>")
    }
    [void]$sb.AppendLine("</table>")
    if ($hourSpikes.Count -gt 0) {
        [void]$sb.AppendLine("<div class='note'><b>Per-hour traffic anomalies detected (today vs normal for that hour):</b>")
        [void]$sb.AppendLine("<table><tr><th>Hour</th><th>Today</th><th>Normal</th><th>vs normal</th></tr>")
        foreach ($s in $hourSpikes) { [void]$sb.AppendLine("<tr><td>$($s.Hour)</td><td>$($s.Count)</td><td>$($s.Baseline)</td><td>$($s.VsNormal)x</td></tr>") }
        [void]$sb.AppendLine("</table></div>")
    } else {
        [void]$sb.AppendLine("<p class='ok'>No per-hour traffic anomalies vs historical baseline.</p>")
    }
} else {
    [void]$sb.AppendLine("<div class='note'>Spike detection requires a history file. Re-run with <code>-HistoryPath &lt;file.json&gt;</code>; after 3+ daily runs, this section flags hours that deviate sharply from their own historical baseline.</div>")
}

# failures
[void]$sb.AppendLine("<h2>5. Delivery failures / NDRs</h2>")
$frCls = if ($failureRate -ge 5) { 'crit' } elseif ($failureRate -ge 2) { 'warn' } else { 'ok' }
[void]$sb.AppendLine("<p>Failed messages: <b>$failedCount</b> &nbsp; Failure rate: <span class='$frCls'>$failureRate%</span> &nbsp; NDRs generated (DSN): $dsnCount</p>")
[void]$sb.AppendLine("<table><tr><th>Status code</th><th>Count</th><th>Meaning</th></tr>")
foreach ($c in $topCodes) { [void]$sb.AppendLine("<tr><td>$($c.StatusCode)</td><td>$($c.Count)</td><td>$(HtmlEncode (Get-StatusCodeMeaning $c.StatusCode))</td></tr>") }
[void]$sb.AppendLine("</table>")
if ($failSamples.Count -gt 0) {
    [void]$sb.AppendLine("<p class='muted'>Sample failures (up to 15):</p>")
    [void]$sb.AppendLine("<table><tr><th>Time</th><th>Sender</th><th>Recipient</th><th>Code</th><th>Subject</th></tr>")
    foreach ($s in $failSamples) {
        [void]$sb.AppendLine("<tr><td>$('{0:HH:mm}' -f $s.Time)</td><td>$(HtmlEncode $s.Sender)</td><td>$(HtmlEncode $s.Recipient)</td><td>$(HtmlEncode $s.Code)</td><td>$(HtmlEncode $s.Subject)</td></tr>")
    }
    [void]$sb.AppendLine("</table>")
}

# latency
[void]$sb.AppendLine("<h2>6. Latency (on-prem transport transit)</h2>")
if ($latencies.Count -gt 0) {
    [void]$sb.AppendLine("<p class='muted'>Based on $($latencies.Count) messages with matched RECEIVE and DELIVER/SEND events. Measures time inside on-prem transport, not end-to-end delivery.</p>")
    [void]$sb.AppendLine("<div class='cards'>")
    foreach ($x in @(@{l='Average (s)';n=$latAvg},@{l='Median (s)';n=$latMed},@{l='p95 (s)';n=$latP95},@{l='Max (s)';n=$latMax})) {
        [void]$sb.AppendLine("<div class='card'><div class='n'>$($x.n)</div><div class='l'>$($x.l)</div></div>")
    }
    [void]$sb.AppendLine("</div>")
} else {
    [void]$sb.AppendLine("<p class='muted'>No correlated messages available to compute latency in this window.</p>")
}

# queues
[void]$sb.AppendLine("<h2>7. Transport queues (point-in-time snapshot)</h2>")
[void]$sb.AppendLine("<p class='muted'>Captured at report run time. Flags at &ge; $QueueWarnCount messages or &ge; $QueueWarnAgeMinutes min old.</p>")
if ($queueRows.Count -gt 0) {
    [void]$sb.AppendLine("<table><tr><th>Server</th><th>Queue</th><th>Next hop</th><th>Type</th><th>Status</th><th>Count</th><th>Oldest (min)</th><th>Flag</th><th>Last error</th></tr>")
    foreach ($q in $queueRows) {
        $cls = if ($q.Flag) { "class='crit'" } else { '' }
        [void]$sb.AppendLine("<tr><td>$($q.Server)</td><td>$(HtmlEncode $q.Queue)</td><td>$(HtmlEncode $q.NextHop)</td><td>$($q.DeliveryType)</td><td>$($q.Status)</td><td>$($q.Count)</td><td>$($q.OldestMin)</td><td $cls>$($q.Flag)</td><td>$(HtmlEncode $q.LastError)</td></tr>")
    }
    [void]$sb.AppendLine("</table>")
} else {
    [void]$sb.AppendLine("<p class='ok'>All monitored queues empty / healthy.</p>")
}

# security / exceptions
[void]$sb.AppendLine("<h2>8. Security &amp; exceptions</h2>")
[void]$sb.AppendLine("<p>On-prem policy rejections (5.7.x) seen in tracking: <b>$policyRejects</b></p>")
if ($agentSummary -and @($agentSummary).Count -gt 0) {
    [void]$sb.AppendLine("<table><tr><th>Agent action</th><th>Count</th></tr>")
    foreach ($a in $agentSummary) { [void]$sb.AppendLine("<tr><td>$(HtmlEncode $a.Action)</td><td>$($a.Count)</td></tr>") }
    [void]$sb.AppendLine("</table>")
}
if ($agentNote) { [void]$sb.AppendLine("<div class='note'>$agentNote</div>") }

# transport rules
[void]$sb.AppendLine("<h2>9. Transport rules</h2>")
[void]$sb.AppendLine("<p class='muted'>Approx. messages touched by the transport rule agent (AGENTINFO): <b>$ruleAgentTouches</b></p>")
if ($ruleRows -and @($ruleRows).Count -gt 0) {
    [void]$sb.AppendLine("<table><tr><th>Priority</th><th>Rule</th><th>State</th></tr>")
    foreach ($r in $ruleRows) { [void]$sb.AppendLine("<tr><td>$($r.Priority)</td><td>$(HtmlEncode $r.Name)</td><td>$($r.State)</td></tr>") }
    [void]$sb.AppendLine("</table>")
}
[void]$sb.AppendLine("<div class='note'>$ruleNote</div>")

# services
[void]$sb.AppendLine("<h2>10. Service health</h2>")
[void]$sb.AppendLine("<table><tr><th>Server</th><th>Role</th><th>Required running</th><th>Not running</th></tr>")
foreach ($s in $serviceRows) {
    $cls = if ($s.RequiredRunning -eq $true) { "class='ok'" } else { "class='crit'" }
    [void]$sb.AppendLine("<tr><td>$($s.Server)</td><td>$(HtmlEncode $s.Role)</td><td $cls>$($s.RequiredRunning)</td><td>$(HtmlEncode $s.ServicesNotRunning)</td></tr>")
}
[void]$sb.AppendLine("</table>")

# component state
[void]$sb.AppendLine("<h2>11. Component state (non-Active only)</h2>")
if ($componentRows.Count -gt 0) {
    [void]$sb.AppendLine("<table><tr><th>Server</th><th>Component</th><th>State</th></tr>")
    foreach ($c in $componentRows) { [void]$sb.AppendLine("<tr><td>$($c.Server)</td><td>$(HtmlEncode $c.Component)</td><td class='warn'>$($c.State)</td></tr>") }
    [void]$sb.AppendLine("</table>")
    [void]$sb.AppendLine("<p class='muted'>Note: a HubTransport component in Draining/Inactive will hold mail. Confirm this is intentional (maintenance) before acting.</p>")
} else {
    [void]$sb.AppendLine("<p class='ok'>All server components Active.</p>")
}

[void]$sb.AppendLine("<hr><p class='muted'>Read-only report. Volume = distinct MessageId deduplicated across servers. Direction = logical (accepted-domain) classification. Queues = point-in-time. Spam/malware filtering is primarily upstream in EOP.</p>")
[void]$sb.AppendLine("</body></html>")

# ---------------------------------------------------------- write file ---

if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$fileName = "MailFlowReport_{0}.html" -f ($windowStart.ToString('yyyyMMdd'))
$outFile  = Join-Path $OutputFolder $fileName
$sb.ToString() | Set-Content -Path $outFile -Encoding UTF8
Write-Step "Report written: $outFile"

# ---------------------------------------------------------- email ---

if ($SendEmail) {
    if (-not $To -or -not $From -or -not $SmtpServer) {
        Write-Warn "SendEmail requested but -To/-From/-SmtpServer not all supplied. Skipping email."
    } else {
        try {
            Send-MailMessage -To $To -From $From -SmtpServer $SmtpServer `
                -Subject ("Exchange mail flow report [$verdict] - $windowLabel") `
                -Body ($sb.ToString()) -BodyAsHtml -ErrorAction Stop
            Write-Step "Report emailed to $To."
        } catch {
            Write-Warn "Email send failed: $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------- console summary ---

Write-Host ""
Write-Host "==================== SUMMARY ====================" -ForegroundColor Green
Write-Host ("Window     : {0}" -f $windowLabel)
Write-Host ("Verdict    : {0}" -f $verdict)
Write-Host ("Total msgs : {0}  (In {1} / Out {2} / Int {3})" -f $totalMessages,$inbound,$outbound,$internal)
Write-Host ("Failures   : {0}  ({1}%)" -f $failedCount,$failureRate)
Write-Host ("Peak hour  : {0:00}:00  ({1} msgs)" -f $peakHour,$peakVal)
if ($hourSpikes.Count) { Write-Host ("Spikes     : {0} hour(s) anomalous vs baseline" -f $hourSpikes.Count) -ForegroundColor Yellow }
if ($queueAlert)       { Write-Host  "Queues     : attention needed" -ForegroundColor Yellow }
if ($serviceAlert)     { Write-Host  "Services   : one or more required services not running" -ForegroundColor Red }
if ($componentAlert)   { Write-Host  "Components : non-Active component(s) present" -ForegroundColor Yellow }
Write-Host ("Report     : {0}" -f $outFile)
Write-Host "================================================" -ForegroundColor Green