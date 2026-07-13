<#
.SYNOPSIS
Test-ExchangeServerHealth_SE.ps1 - Exchange Server Health Check Script (Modernized for Exchange SE).

.DESCRIPTION 
Performs a series of health checks on Exchange servers and DAGs
and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

Supports Exchange Server 2016, 2019, and Subscription Edition (SE).
Legacy Exchange 2003/2007/2010/2013 code paths have been removed.

Use the ignorelist.txt file to specify any servers, DAGs, or databases you
want the script to ignore (eg test/dev servers).

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.PARAMETER Server
Perform a health check of a single server

.PARAMETER ReportMode
Set to $true to generate a HTML report. A default file name is used if none is specified.

.PARAMETER ReportFile
Allows you to specify a different HTML report file name than the default.

.PARAMETER SendEmail
Sends the HTML report via email using the SMTP configuration within the script.

.PARAMETER AlertsOnly
Only sends the email report if at least one error or warning was detected.

.PARAMETER Log
Writes a log file to help with troubleshooting.

.EXAMPLE
.\Test-ExchangeServerHealth_SE.ps1
Checks all servers in the organization and outputs the results to the shell window.

.EXAMPLE
.\Test-ExchangeServerHealth_SE.ps1 -Server EX-MB01
Checks the server EX-MB01 and outputs the results to the shell window.

.EXAMPLE
.\Test-ExchangeServerHealth_SE.ps1 -ReportMode -SendEmail
Checks all servers, outputs results to shell, HTML report, and emails the report.

.NOTES
Original script by Paul Cunningham
https://github.com/cunninghamp

Modernized for Exchange SE.
- Added Exchange Server SE (Subscription Edition) detection
- Replaced WMI with CIM cmdlets
- Removed Unified Messaging checks (removed in SE)
- Removed legacy Public Folder Database checks (not applicable since 2013+)
- Removed Exchange 2003/2007/2010/2013 code paths
- Improved module/snapin loading for modern Exchange
- Updated #requires to PowerShell 5.1
- Added Test-Connection -Count 1 for faster ping
- Improved content index state handling

License: MIT (inherited from original)
#>

#requires -version 5.1

[CmdletBinding()]
param (
        [Parameter( Mandatory=$false)]
        [string]$Server,

        [Parameter( Mandatory=$false)]
        [string]$ServerList,    
        
        [Parameter( Mandatory=$false)]
        [string]$ReportFile="exchangeserverhealth_SE.html",

        [Parameter( Mandatory=$false)]
        [switch]$ReportMode,
        
        [Parameter( Mandatory=$false)]
        [switch]$SendEmail,

        [Parameter( Mandatory=$false)]
        [switch]$AlertsOnly,    
        
        [Parameter( Mandatory=$false)]
        [switch]$Log
    )


#...................................
# Variables
#...................................

$now = Get-Date
$date = $now.ToShortDateString()
[array]$exchangeservers = @()
[int]$transportqueuehigh = 100
[int]$transportqueuewarn = 80
$mapitimeout = 10
$pass = "Green"
$warn = "Yellow"
$fail = "Red"
$ip = $null
[array]$serversummary = @()
[array]$dagsummary = @()
[array]$report = @()
[bool]$alerts = $false
[array]$dags = @()
[array]$dagdatabases = @()
[int]$replqueuewarning = 8
$dagreportbody = $null

$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path

#...................................
# Modify these Variables (optional)
#...................................

$reportemailsubject = "Exchange Server Health Report"
$ignorelistfile = "$myDir\ignorelist.txt"
$logfile = "$myDir\exchangeserverhealth.log"


#...................................
# Modify these Email Settings
#...................................

$smtpsettings = @{
    To =  "exchangeadmins@yourdomain.com"
    From = "exchangehealth@yourdomain.com"
    Subject = "$reportemailsubject - $now"
    SmtpServer = "smtp.yourdomain.com"
    }

#...................................
# Localization strings
#...................................

# The server roles must match the role names returned by Test-ServiceHealth
$casrole = "Client Access Server Role"
$htrole = "Hub Transport Server Role"
$mbrole = "Mailbox Server Role"

# Result string for successful Test-MAPIConnectivity
$success = "Success"


#...................................
# Logfile Strings
#...................................

$logstring0 = "====================================="
$logstring1 = " Exchange Server Health Check"

#...................................
# Initialization Strings
#...................................

$initstring0 = "Initializing..."
$initstring1 = "Loading Exchange PowerShell module/snapin"
$initstring2 = "Exchange PowerShell could not be loaded."
$initstring3 = "Setting scope to entire forest"

#...................................
# Error/Warning Strings
#...................................

$string0 = "Server is not an Exchange server. "
$string1 = "Server is not reachable. "
$string3 = "------ Checking"
$string4 = "Could not test service health. "
$string5 = "required services not running. "
$string6 = "Could not check queue. "
$string8 = "Skipping Edge Transport server. "
$string9 = "Mailbox databases not mounted. "
$string10 = "MAPI tests failed. "
$string11 = "Mail flow test failed. "
$string13 = "Server not found in DNS. "
$string14 = "Sending email. "
$string15 = "Done."
$string16 = "------ Finishing"
$string17 = "Unable to retrieve uptime. "
$string18 = "Ping failed. "
$string19 = "No alerts found, and AlertsOnly switch was used. No email sent. "
$string20 = "You have specified a single server to check"
$string21 = "Couldn't find the server $server. Script will terminate."
$string22 = "The file $ignorelistfile could not be found. No servers, DAGs or databases will be ignored."
$string23 = "You have specified a filename containing a list of servers to check"
$string24 = "The file $serverlist could not be found. Script will terminate."
$string25 = "Retrieving server list"
$string26 = "Removing servers in ignorelist from server list"
$string27 = "Beginning the server health checks"
$string28 = "Servers, DAGs and databases to ignore:"
$string29 = "Servers to check:"
$string30 = "Checking DNS"
$string31 = "DNS check passed"
$string32 = "Checking ping"
$string33 = "Ping test passed"
$string34 = "Checking uptime"
$string35 = "Checking service health"
$string36 = "Checking Hub Transport Server"
$string37 = "Checking Mailbox Server"
$string38 = "Ignore list contains no server names."
$string41 = "Checking mailbox databases"
$string42 = "Mailbox database status is"
$string43 = "Offline databases: "
$string44 = "Checking MAPI connectivity"
$string45 = "MAPI connectivity status is"
$string46 = "MAPI failed to: "
$string47 = "Checking mail flow"
$string48 = "Mail flow status is"
$string49 = "No active DBs"
$string50 = "Finished checking server"
$string51 = "Skipped"
$string60 = "Beginning the DAG health checks"
$string61 = "Could not determine server with active database copy"
$string62 = "mounted on server that is activation preference"
$string63 = "unhealthy database copy count is"
$string64 = "healthy copy/replay queue count is"
$string65 = "(of"
$string66 = ")"
$string67 = "unhealthy content index count is"
$string68 = "DAGs to check:"
$string69 = "DAG databases to check"


#...................................
# Functions
#...................................

#This function is used to generate HTML for the DAG member health report
Function New-DAGMemberHTMLTableCell()
{
    param( $lineitem )
    
    $htmltablecell = $null

    switch ($($line."$lineitem"))
    {
        $null { $htmltablecell = "<td>n/a</td>" }
        "Passed" { $htmltablecell = "<td class=""pass"">$($line."$lineitem")</td>" }
        default { $htmltablecell = "<td class=""warn"">$($line."$lineitem")</td>" }
    }
    
    return $htmltablecell
}

#This function is used to generate HTML for the server health report
Function New-ServerHealthHTMLTableCell()
{
    param( $lineitem )
    
    $htmltablecell = $null
    
    switch ($($reportline."$lineitem"))
    {
        $success {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Success" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Pass" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Warn" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Access Denied" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Fail" {$htmltablecell = "<td class=""fail"">$($reportline."$lineitem")</td>"}
        "Could not test service health. " {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Unknown" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        default {$htmltablecell = "<td>$($reportline."$lineitem")</td>"}
    }
    
    return $htmltablecell
}

#This function is used to write the log file if -Log is used
Function Write-Logfile()
{
    param( $logentry )
    $timestamp = Get-Date -DisplayHint Time
    "$timestamp $logentry" | Out-File $logfile -Append
}


#This function determines the friendly Exchange version string
Function Get-ExchangeVersionString()
{
    param( [string]$AdminDisplayVersion )
    
    if ($AdminDisplayVersion -like "Version 15.1*")
    {
        return "Exchange 2016"
    }
    
    if ($AdminDisplayVersion -like "Version 15.2*")
    {
        # Exchange SE RTM starts at build 15.2.1544.x
        # Extract build number to differentiate 2019 from SE
        if ($AdminDisplayVersion -match "Build\s+(\d+)\.")
        {
            $buildNumber = [int]$Matches[1]
            if ($buildNumber -ge 1544)
            {
                return "Exchange SE"
            }
        }
        return "Exchange 2019"
    }
    
    return "Unknown"
}

#This function tests mail flow via remote PSSession (for modern Exchange)
Function Test-ModernMailFlow()
{
    param ( $mailboxserver )

    $mailflowresult = $null
    
    Write-Verbose "Creating PSSession for $mailboxserver"
    $url = (Get-PowerShellVirtualDirectory -Server $mailboxserver -AdPropertiesOnly | Where-Object {$_.Name -eq "Powershell (Default Web Site)"}).InternalURL.AbsoluteUri
    if ($null -eq $url)
    {
        $url = "http://$mailboxserver/powershell"
    }

    try
    {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url -ErrorAction STOP
    }
    catch
    {
        Write-Verbose "Failed to create PSSession: $($_.Exception.Message)"
        if ($Log) {Write-LogFile $_.Exception.Message}
        Write-Warning $_.Exception.Message
        $mailflowresult = "Fail"
    }

    if ($null -ne $session)
    {
        try
        {
            Write-Verbose "Running mail flow test on $mailboxserver"
            $result = Invoke-Command -Session $session {Test-Mailflow} -ErrorAction STOP
            $mailflowresult = $result.TestMailflowResult
        }
        catch
        {
            Write-Verbose "Mail flow test error: $($_.Exception.Message)"
            if ($Log) {Write-LogFile $_.Exception.Message}
            Write-Warning $_.Exception.Message
            $mailflowresult = "Fail"
        }

        Write-Verbose "Mail flow test: $mailflowresult"
        Write-Verbose "Removing PSSession"
        Remove-PSSession $session.Id
    }

    return $mailflowresult
}


#...................................
# Initialize
#...................................

# Log file is overwritten each time the script is run
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$timestamp $logstring0" | Out-File $logfile
    Write-Logfile $logstring1
    Write-Logfile "  $now"
    Write-Logfile $logstring0
}

Write-Host $initstring0
if ($Log) {Write-Logfile $initstring0}

# Load Exchange PowerShell - try multiple methods for compatibility
if (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)
{
    Write-Verbose "Exchange cmdlets already available in this session"
}
elseif (Get-PSSnapin -Registered -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "Microsoft.Exchange.Management.PowerShell.SnapIn"})
{
    # Exchange 2016/2019/SE snapin
    Write-Verbose $initstring1
    if ($Log) {Write-Logfile $initstring1}
    try
    {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction STOP
    }
    catch
    {
        Write-Verbose $initstring2
        if ($Log) {Write-Logfile $initstring2}
        Write-Warning $_.Exception.Message
        EXIT
    }
}
elseif (Get-PSSnapin -Registered -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010"})
{
    # Fallback to E2010 snapin (works for 2010-2019)
    Write-Verbose $initstring1
    if ($Log) {Write-Logfile $initstring1}
    try
    {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction STOP
    }
    catch
    {
        Write-Verbose $initstring2
        if ($Log) {Write-Logfile $initstring2}
        Write-Warning $_.Exception.Message
        EXIT
    }
    . $env:ExchangeInstallPath\bin\RemoteExchange.ps1
    Connect-ExchangeServer -auto -AllowClobber
}
else
{
    Write-Warning $initstring2
    if ($Log) {Write-Logfile $initstring2}
    EXIT
}

# Set scope to include entire forest
Write-Verbose $initstring3
if ($Log) {Write-Logfile $initstring3}
if (!(Get-ADServerSettings).ViewEntireForest)
{
    Set-ADServerSettings -ViewEntireForest $true -WarningAction SilentlyContinue
}


#...................................
# Script
#...................................

# Check if a single server was specified
if ($server)
{
    [bool]$NoDAG = $true
    Write-Verbose $string20
    if ($Log) {Write-Logfile $string20}
    try
    {
        $exchangeservers = Get-ExchangeServer $server -ErrorAction STOP
    }
    catch
    {
        Write-Verbose $string21
        if ($Log) {Write-Logfile $string21}
        Write-Error $_.Exception.Message
        EXIT
    }
}
elseif ($serverlist)
{
    [bool]$NoDAG = $true
    Write-Verbose $string23
    if ($Log) {Write-Logfile $string23}
    try
    {
        $tmpservers = @(Get-Content $serverlist -ErrorAction STOP)
        $exchangeservers = @($tmpservers | Get-ExchangeServer)
    }
    catch
    {
        Write-Verbose $string24
        if ($Log) {Write-Logfile $string24}
        Write-Error $_.Exception.Message
        EXIT
    }
}
else
{
    # Load ignore list
    try
    {
        $ignorelist = @(Get-Content $ignorelistfile -ErrorAction STOP)
        if ($Log) {Write-Logfile $string28}
        if ($Log) {
            if ($($ignorelist.count) -gt 0)
            {
                foreach ($line in $ignorelist)
                {
                    Write-Logfile "- $line"
                }
            }
            else
            {
                Write-Logfile $string38
            }
        }
    }
    catch
    {
        Write-Warning $string22
        if ($Log) {Write-Logfile $string22}
    }
    
    # Get all servers (only 2016/2019/SE - filter out anything older)
    Write-Verbose $string25
    if ($Log) {Write-Logfile $string25}
    $GetExchangeServerResults = @(Get-ExchangeServer | Where-Object {$_.AdminDisplayVersion -like "Version 15.*"} | Sort-Object site,name)
    
    # Remove ignored servers
    Write-Verbose $string26
    if ($Log) {Write-Logfile $string26}
    foreach ($tmpserver in $GetExchangeServerResults)
    {
        if (!($ignorelist -icontains $tmpserver.name))
        {
            $exchangeservers = $exchangeservers += $tmpserver.identity
        }
    }

    if ($Log) {Write-Logfile $string29}
    if ($Log) {
        foreach ($svr in $exchangeservers)
        {
            Write-Logfile "- $svr"
        }
    }
}


### Begin the Exchange Server health checks
Write-Verbose $string27
if ($Log) {Write-Logfile $string27}

foreach ($server in $exchangeservers)
{
    Write-Host -ForegroundColor White "$string3 $server"
    if ($Log) {Write-Logfile "$string3 $server"}
    
    # Get server info
    try
    {
        $serverinfo = Get-ExchangeServer $server -ErrorAction Stop
    }
    catch
    {
        Write-Warning $_.Exception.Message
        if ($Log) {Write-Logfile $_.Exception.Message}
        $serverinfo = $null
    }

    if ($null -eq $serverinfo)
    {
        Write-Host -ForegroundColor $warn $string0
        if ($Log) {Write-Logfile $string0}
    }
    elseif ($serverinfo.IsEdgeServer)
    {
        Write-Host -ForegroundColor White $string8
        if ($Log) {Write-Logfile $string8}
    }
    else
    {
        # Server is a valid Exchange server - begin health check
        $serverObj = New-Object PSObject
        $serverObj | Add-Member NoteProperty -Name "Server" -Value $server
        
        $site = ($serverinfo.site.ToString()).Split("/")
        $serverObj | Add-Member NoteProperty -Name "Site" -Value $site[-1]
        
        # Initialize properties
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Version" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Roles" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Client Access Server Role Services" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Hub Transport Server Role Services" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Mailbox Server Role Services" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Queue Length" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "MB DBs Mounted" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "MAPI Test" -Value "n/a"

        # DNS Check
        if ($Log) {Write-Logfile $string30}
        Write-Host "DNS Check: " -NoNewline
        try 
        {
            $ip = @([System.Net.Dns]::GetHostByName($server).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)
        }
        catch
        {
            Write-Host -ForegroundColor $warn $_.Exception.Message
            if ($Log) {Write-Logfile $_.Exception.Message}
            $ip = $null
        }

        if ($null -ne $ip)
        {
            Write-Host -ForegroundColor $pass "Pass"
            if ($Log) {Write-Logfile $string31}
            $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force

            # Ping Check
            if ($Log) {Write-Logfile $string32}
            Write-Host "Ping Check: " -NoNewline
            
            $ping = $null
            try
            {
                $ping = Test-Connection $server -Count 1 -Quiet -ErrorAction Stop
            }
            catch
            {
                Write-Host -ForegroundColor $warn $_.Exception.Message
                if ($Log) {Write-Logfile $_.Exception.Message}
            }

            switch ($ping)
            {
                $true {
                    Write-Host -ForegroundColor $pass "Pass"
                    $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                    if ($Log) {Write-Logfile $string33}
                    }
                default {
                    Write-Host -ForegroundColor $fail "Fail"
                    $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                    $serversummary += "$server - $string18"
                    if ($Log) {Write-Logfile $string18}
                    }
            }

            
            # Uptime check using CIM (replaces WMI)
            if ($Log) {Write-Logfile $string34}
            [int]$uptime = $null
            $OS = $null
        
            try 
            {
                $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $server -ErrorAction STOP
            }
            catch
            {
                Write-Host -ForegroundColor $warn $_.Exception.Message
                if ($Log) {Write-Logfile $_.Exception.Message}
            }
            
            Write-Host "Uptime (hrs): " -NoNewline

            if ($null -eq $OS)
            {
                [string]$uptime = $string17
                if ($Log) {Write-Logfile $string17}
                $serversummary += "$server - $string17"
            }
            else
            {
                # CIM returns LastBootUpTime as a proper DateTime object
                $timespan = (Get-Date) - $OS.LastBootUpTime
                [int]$uptime = "{0:00}" -f $timespan.TotalHours
                Switch ($uptime -gt 23) {
                    $true { Write-Host -ForegroundColor $pass $uptime }
                    $false { Write-Host -ForegroundColor $warn $uptime; $serversummary += "$server - Uptime is less than 24 hours" }
                    default { Write-Host -ForegroundColor $warn $uptime; $serversummary += "$server - Uptime is less than 24 hours" }
                }
            }

            if ($Log) {Write-Logfile "Uptime is $uptime hours"}
            $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptime -Force    

            
            if ($ping -or ($uptime -ne $string17))
            {
                # Determine Exchange version
                $ExVer = $serverinfo.AdminDisplayVersion
                Write-Host "Server version: " -NoNewline
                
                $version = Get-ExchangeVersionString -AdminDisplayVersion $ExVer
                
                Write-Host $version
                if ($Log) {Write-Logfile "Server is running $version"}
                $serverObj | Add-Member NoteProperty -Name "Version" -Value $version -Force
            
                if ($version -eq "Unknown")
                {
                    Write-Host -ForegroundColor $warn "Unsupported Exchange version detected: $ExVer"
                    if ($Log) {Write-Logfile "Unsupported Exchange version: $ExVer"}
                }
                else
                {
                    # Exchange 2016/2019/SE Health Checks
                    Write-Host "Roles:" $serverinfo.ServerRole
                    if ($Log) {Write-Logfile "Server roles: $($serverinfo.ServerRole)"}
                    $serverObj | Add-Member NoteProperty -Name "Roles" -Value $serverinfo.ServerRole -Force
                    
                    $IsEdge = $serverinfo.IsEdgeServer        
                    $IsHub = $serverinfo.IsHubTransportServer
                    $IsCAS = $serverinfo.IsClientAccessServer
                    $IsMB = $serverinfo.IsMailboxServer


                    #START - General Server Health Check (Service Health)
                    if ($IsEdge -ne $true)
                    {
                        if ($Log) {Write-Logfile $string35}
                        $servicehealth = @()
                        try {
                            $servicehealth = @(Test-ServiceHealth $server -ErrorAction Stop)
                        }
                        catch {
                            $serversummary += "$server - $string4"
                            Write-Host -ForegroundColor $warn $string4 ":" $_.Exception.Message
                            if ($Log) {Write-Logfile $_.Exception.Message}
                            $serverObj | Add-Member NoteProperty -Name "Client Access Server Role Services" -Value $string4 -Force
                            $serverObj | Add-Member NoteProperty -Name "Hub Transport Server Role Services" -Value $string4 -Force
                            $serverObj | Add-Member NoteProperty -Name "Mailbox Server Role Services" -Value $string4 -Force
                        }
                            
                        if ($servicehealth)
                        {
                            foreach($s in $servicehealth)
                            {
                                $roleName = $s.Role
                                Write-Host $roleName "Services: " -NoNewline
                                                            
                                switch ($s.RequiredServicesRunning)
                                {
                                    $true {
                                            $svchealth = "Pass"
                                            Write-Host -ForegroundColor $pass "Pass"
                                        }
                                    $false {
                                            $svchealth = "Fail"
                                            Write-Host -ForegroundColor $fail "Fail"
                                            $serversummary += "$server - $rolename $string5"
                                        }
                                    default {
                                            $svchealth = "Warn"
                                            Write-Host -ForegroundColor $warn "Warning"
                                            $serversummary += "$server - $rolename $string5"
                                        }
                                }

                                switch ($s.Role)
                                {
                                    $casrole { $serverinfoservices = "Client Access Server Role Services" }
                                    $htrole { $serverinfoservices = "Hub Transport Server Role Services" }
                                    $mbrole { $serverinfoservices = "Mailbox Server Role Services" }
                                    default { 
                                        # Skip Unified Messaging or any other unknown roles
                                        $serverinfoservices = $null
                                    }
                                }
                                if ($serverinfoservices) {
                                    if ($Log) {Write-Logfile "$serverinfoservices status is $svchealth"}    
                                    $serverObj | Add-Member NoteProperty -Name $serverinfoservices -Value $svchealth -Force
                                }
                            }
                        }
                    }
                    #END - General Server Health Check


                    #START - Transport Queue Check
                    if ($IsHub)
                    {
                        $q = $null
                        if ($Log) {Write-Logfile $string36}
                        Write-Host "Total Queue: " -NoNewline
                        try {
                            $q = Get-Queue -server $server -ErrorAction Stop | Where-Object {$_.DeliveryType -ne "ShadowRedundancy"}
                        }
                        catch {
                            $serversummary += "$server - $string6"
                            Write-Host -ForegroundColor $warn $string6
                            Write-Warning $_.Exception.Message
                            if ($Log) {Write-Logfile $string6}
                            if ($Log) {Write-Logfile $_.Exception.Message}
                        }
                        
                        if ($q)
                        {
                            $qcount = $q | Measure-Object MessageCount -Sum
                            [int]$qlength = $qcount.sum
                            $serverObj | Add-Member NoteProperty -Name "Queue Length" -Value $qlength -Force
                            if ($Log) {Write-Logfile "Queue length is $qlength"}
                            if ($qlength -le $transportqueuewarn)
                            {
                                Write-Host -ForegroundColor $pass $qlength
                                $serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Pass ($qlength)" -Force
                            }
                            elseif ($qlength -gt $transportqueuewarn -and $qlength -lt $transportqueuehigh)
                            {
                                Write-Host -ForegroundColor $warn $qlength
                                $serversummary += "$server - Transport queue is above warning threshold" 
                                $serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Warn ($qlength)" -Force
                            }
                            else
                            {
                                Write-Host -ForegroundColor $fail $qlength
                                $serversummary += "$server - Transport queue is above high threshold"
                                $serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Fail ($qlength)" -Force
                            }
                        }
                        else
                        {
                            $serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Unknown" -Force
                        }
                    }
                    #END - Transport Queue Check


                    #START - Mailbox Server Check
                    if ($IsMB)
                    {
                        if ($Log) {Write-Logfile $string37}
                        
                        # Get mailbox databases (no more public folder databases in 2013+)
                        [array]$mbdbs = @(Get-MailboxDatabase -server $server -status | Where-Object {$_.Recovery -ne $true})
                        [array]$activedbs = @(Get-MailboxDatabase -server $server -status | Where-Object {$_.Recovery -ne $true -and $_.MountedOnServer -eq ($serverinfo.fqdn)})
                        
                        #START - Database Mount Check
                        if ($mbdbs.count -gt 0)
                        {
                            if ($Log) {Write-Logfile $string41}
                        
                            [string]$mbdbstatus = "Pass"
                            [array]$alertdbs = @()

                            Write-Host "Mailbox databases mounted: " -NoNewline
                            foreach ($db in $mbdbs)
                            {
                                if (($db.mounted) -ne $true)
                                {
                                    $mbdbstatus = "Fail"
                                    $alertdbs += $db.name
                                }
                            }

                            $serverObj | Add-Member NoteProperty -Name "MB DBs Mounted" -Value $mbdbstatus -Force
                            if ($Log) {Write-Logfile "$string42 $mbdbstatus"}
                            
                            if ($alertdbs.count -eq 0)
                            {
                                Write-Host -ForegroundColor $pass $mbdbstatus
                            }
                            else
                            {
                                $serversummary += "$server - $string9"
                                Write-Host -ForegroundColor $fail $mbdbstatus
                                Write-Host $string43
                                if ($Log) {Write-Logfile $string43}
                                foreach ($al in $alertdbs)
                                {
                                    Write-Host -ForegroundColor $fail "`t$al"
                                    if ($Log) {Write-Logfile "- $al"}
                                }
                            }
                        }
                        #END - Database Mount Check

                        
                        #START - MAPI Connectivity Test
                        if ($activedbs.count -gt 0)
                        {
                            [string]$mapiresult = "Unknown"
                            [array]$alertdbs = @()
                            if ($Log) {Write-Logfile $string44}
                            Write-Host "MAPI connectivity: " -NoNewline
                            foreach ($db in $mbdbs)
                            {
                                # Use string name to avoid deserialized ADObjectId type mismatch in remote PS sessions
                                $mapistatus = Test-MapiConnectivity -Database $db.Name -PerConnectionTimeout $mapitimeout
                                if ($null -eq $mapistatus.Result.Value)
                                {
                                    $mapiresult = "$($mapistatus.Result)"
                                }
                                else
                                {
                                    $mapiresult = "$($mapistatus.Result.Value)"
                                }
                                if ($mapiresult -ne "Success")
                                {
                                    $alertdbs += $db.name
                                }
                            }

                            $serverObj | Add-Member NoteProperty -Name "MAPI Test" -Value $mapiresult -Force
                            if ($Log) {Write-Logfile "$string45 $mapiresult"}
                            
                            if ($alertdbs.count -eq 0)
                            {
                                Write-Host -ForegroundColor $pass $mapiresult
                            }
                            else
                            {
                                $serversummary += "$server - $string10"
                                Write-Host -ForegroundColor $fail $mapiresult
                                Write-Host $string46
                                if ($Log) {Write-Logfile $string46}
                                foreach ($al in $alertdbs)
                                {
                                    Write-Host -ForegroundColor $fail "`t$al"
                                    if ($Log) {Write-Logfile "- $al"}
                                }
                            }
                        }
                        #END - MAPI Connectivity Test

                        
                        #START - Mail Flow Test
                        if ($activedbs.count -gt 0)
                        {
                            if ($Log) {Write-Logfile $string47}
                            Write-Host "Mail flow test: " -NoNewline
                            
                            $mailflowresult = $null
                            
                            # Try direct Test-Mailflow first
                            try
                            {
                                $flow = Test-Mailflow $server -ErrorAction Stop
                                $mailflowresult = $flow.TestMailflowResult
                            }
                            catch
                            {
                                # Fall back to remote session method
                                Write-Verbose "Direct mail flow test failed, trying remote session method"
                                $mailflowresult = Test-ModernMailFlow -mailboxserver $server
                            }
                            
                            if ($mailflowresult -eq "Success" -or $mailflowresult -eq $success)
                            {
                                Write-Host -ForegroundColor $pass $mailflowresult
                                $serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "Pass" -Force
                            }
                            else
                            {
                                $serversummary += "$server - $string11"
                                Write-Host -ForegroundColor $fail $mailflowresult
                                $serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "Fail" -Force
                            }
                            
                            if ($Log) {Write-Logfile "$string48 $mailflowresult"}
                        }
                        else
                        {
                            Write-Host "Mail flow test: No active mailbox databases"
                            $serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value $string49 -Force
                            if ($Log) {Write-Logfile $string49}
                        }
                        #END - Mail Flow Test
                    }
                    #END - Mailbox Server Check

                }
                #END - Exchange Health Checks

                if ($Log) {Write-Logfile "$string50 $server"}
                $report = $report + $serverObj
            }
            else
            {
                # Server is not reachable and uptime could not be retrieved
                Write-Host -ForegroundColor $warn $string1
                if ($Log) {Write-Logfile $string1}
                $serversummary += "$server - $string1"
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                if ($Log) {Write-Logfile "$string50 $server"}
                $report = $report + $serverObj
            }
        }
        else
        {
            Write-Host -ForegroundColor $Fail "Fail"
            Write-Host -ForegroundColor $warn $string13
            if ($Log) {Write-Logfile $string13}
            $serversummary += "$server - $string13"
            $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Fail" -Force
            if ($Log) {Write-Logfile "$string50 $server"}
            $report = $report + $serverObj
        }
    }    
}
### End the Exchange Server health checks


### Begin DAG Health Report

# Skip if -Server or -Serverlist parameter was used
if (!($NoDAG))
{
    if ($Log) {Write-Logfile $string60}
    Write-Verbose "Retrieving Database Availability Groups"

    # Get all DAGs
    $tmpdags = @(Get-DatabaseAvailabilityGroup)
    $tmpstring = "$($tmpdags.count) DAGs found"
    Write-Verbose $tmpstring
    if ($Log) {Write-Logfile $tmpstring}

    # Remove DAGs in ignorelist
    foreach ($tmpdag in $tmpdags)
    {
        if (!($ignorelist -icontains $tmpdag.name))
        {
            $dags += $tmpdag
        }
    }

    $tmpstring = "$($dags.count) DAGs will be checked"
    Write-Verbose $tmpstring
    if ($Log) {Write-Logfile $tmpstring}

    if ($Log) {Write-Logfile $string68}
    if ($Log) {
        foreach ($dag in $dags)
        {
            Write-Logfile "- $dag"
        }
    }
}

if ($($dags.count) -gt 0)
{
    foreach ($dag in $dags)
    {
        # Strings for HTML report
        $dagsummaryintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Health Summary:</p>"
        $dagdetailintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Health Details:</p>"
        $dagmemberintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Member Health:</p>"

        $dagdbcopyReport = @()
        $dagciReport = @()
        $dagmemberReport = @()
        $dagdatabaseSummary = @()
        $dagdatabases = @()
        
        $tmpstring = "---- Processing DAG $($dag.Name)"
        Write-Verbose $tmpstring
        if ($Log) {Write-Logfile $tmpstring}
        
        $dagmembers = @($dag | Select-Object -ExpandProperty Servers | Sort-Object Name)
        $tmpstring = "$($dagmembers.count) DAG members found"
        Write-Verbose $tmpstring
        if ($Log) {Write-Logfile $tmpstring}

        
        # Get all databases in the DAG
        $tmpdatabases = @(Get-MailboxDatabase -Status | Where-Object {$_.Recovery -ne $true -and $_.MasterServerOrAvailabilityGroup -eq $dag.Name} | Sort-Object Name)

        foreach ($tmpdatabase in $tmpdatabases)
        {
            if (!($ignorelist -icontains $tmpdatabase.name))
            {
                $dagdatabases += $tmpdatabase
            }
        }
                
        $tmpstring = "$($dagdatabases.count) DAG databases will be checked"
        Write-Verbose $tmpstring
        if ($Log) {Write-Logfile $tmpstring}

        if ($Log) {Write-Logfile $string69}
        if ($Log) {
            foreach ($database in $dagdatabases)
            {
                Write-Logfile "- $database"
            }
        }
        
        foreach ($database in $dagdatabases)
        {
            $tmpstring = "---- Processing database $database"
            Write-Verbose $tmpstring
            if ($Log) {Write-Logfile $tmpstring}

            $activationPref = $null
            $totalcopies = $null
            $healthycopies = $null
            $unhealthycopies = $null
            $healthyqueues  = $null
            $unhealthyqueues = $null
            $laggedqueues = $null
            $healthyindexes = $null
            $unhealthyindexes = $null

            # Custom object for Database
            $objectHash = @{
                            "Database" = $database.Identity
                            "Mounted on" = "Unknown"
                            "Preference" = $null
                            "Total Copies" = $null
                            "Healthy Copies" = $null
                            "Unhealthy Copies" = $null
                            "Healthy Queues" = $null
                            "Unhealthy Queues" = $null
                            "Lagged Queues" = $null
                            "Healthy Indexes" = $null
                            "Unhealthy Indexes" = $null
                            }
            $databaseObj = New-Object PSObject -Property $objectHash

            $dbcopystatus = @($database | Get-MailboxDatabaseCopyStatus)
            $tmpstring = "$database has $($dbcopystatus.Count) copies"
            Write-Verbose $tmpstring
            if ($Log) {Write-Logfile $tmpstring}

            
            foreach ($dbcopy in $dbcopystatus)
            {
                # Custom object for DB copy
                $objectHash = @{
                                "Database Copy" = $dbcopy.Identity
                                "Database Name" = $dbcopy.DatabaseName
                                "Mailbox Server" = $null
                                "Activation Preference" = $null
                                "Status" = $null
                                "Copy Queue" = $null
                                "Replay Queue" = $null
                                "Replay Lagged" = $null
                                "Truncation Lagged" = $null
                                "Content Index" = $null
                                }
                $dbcopyObj = New-Object PSObject -Property $objectHash
                
                $tmpstring = "Database Copy: $($dbcopy.Identity)"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}
                
                $mailboxserver = $dbcopy.MailboxServer
                $tmpstring = "Server: $mailboxserver"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}

                $pref = ($database | Select-Object -ExpandProperty ActivationPreference | Where-Object {$_.Key -ieq $mailboxserver}).Value
                $tmpstring = "Activation Preference: $pref"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}

                $copystatus = $dbcopy.Status
                $tmpstring = "Status: $copystatus"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}
                
                [int]$copyqueuelength = $dbcopy.CopyQueueLength
                $tmpstring = "Copy Queue: $copyqueuelength"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}
                
                [int]$replayqueuelength = $dbcopy.ReplayQueueLength
                $tmpstring = "Replay Queue: $replayqueuelength"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}

                
                # Content Index state handling - improved for modern Exchange/SE
                if ($($dbcopy.ContentIndexErrorMessage -match "is disabled in Active Directory"))
                {
                    $contentindexstate = "Disabled"
                }
                elseif ($($dbcopy.ContentIndexState -match "NotApplicable") -or $($dbcopy.ContentIndexState -match "11"))
                {
                    $contentindexstate = "Healthy"
                }
                elseif ($($dbcopy.ContentIndexState -match "Running"))
                {
                    # Exchange SE may report "Running" as healthy state
                    $contentindexstate = "Healthy"
                }
                else
                {
                    $contentindexstate = $dbcopy.ContentIndexState
                }
                $tmpstring = "Content Index: $contentindexstate"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}                

                # Checking whether this is a replay lagged copy
                $replaylagcopies = @($database | Select-Object -ExpandProperty ReplayLagTimes | Where-Object {$_.Value -gt 0})
                if ($($replaylagcopies.count) -gt 0)
                {
                    [bool]$replaylag = $false
                    foreach ($replaylagcopy in $replaylagcopies)
                    {
                        if ($replaylagcopy.Key -ieq $mailboxserver)
                        {
                            $tmpstring = "$database is replay lagged on $mailboxserver"
                            Write-Verbose $tmpstring
                            if ($Log) {Write-Logfile $tmpstring}
                            [bool]$replaylag = $true
                        }
                    }
                }
                else
                {
                   [bool]$replaylag = $false
                }
                $tmpstring = "Replay lag is $replaylag"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}                
                        
                # Checking for truncation lagged copies
                $truncationlagcopies = @($database | Select-Object -ExpandProperty TruncationLagTimes | Where-Object {$_.Value -gt 0})
                if ($($truncationlagcopies.count) -gt 0)
                {
                    [bool]$truncatelag = $false
                    foreach ($truncationlagcopy in $truncationlagcopies)
                    {
                        if ($truncationlagcopy.Key -eq $mailboxserver)
                        {
                            $tmpstring = "$database is truncate lagged on $mailboxserver"
                            Write-Verbose $tmpstring
                            if ($Log) {Write-Logfile $tmpstring}                            
                            [bool]$truncatelag = $true
                        }
                    }
                }
                else
                {
                   [bool]$truncatelag = $false
                }
                $tmpstring = "Truncation lag is $truncatelag"
                Write-Verbose $tmpstring
                if ($Log) {Write-Logfile $tmpstring}

                
                $dbcopyObj | Add-Member NoteProperty -Name "Mailbox Server" -Value $mailboxserver -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Activation Preference" -Value $pref -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Status" -Value $copystatus -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Copy Queue" -Value $copyqueuelength -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Replay Queue" -Value $replayqueuelength -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Replay Lagged" -Value $replaylag -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Truncation Lagged" -Value $truncatelag -Force
                $dbcopyObj | Add-Member NoteProperty -Name "Content Index" -Value $contentindexstate -Force
                
                $dagdbcopyReport += $dbcopyObj
            }
        
            $copies = @($dagdbcopyReport | Where-Object { ($_."Database Name" -eq $database) })
        
            $mountedOn = ($copies | Where-Object { ($_.Status -eq "Mounted") })."Mailbox Server"
            if ($mountedOn)
            {
                $databaseObj | Add-Member NoteProperty -Name "Mounted on" -Value $mountedOn -Force
            }
        
            $activationPref = ($copies | Where-Object { ($_.Status -eq "Mounted") })."Activation Preference"
            $databaseObj | Add-Member NoteProperty -Name "Preference" -Value $activationPref -Force

            $totalcopies = $copies.count
            $databaseObj | Add-Member NoteProperty -Name "Total Copies" -Value $totalcopies -Force
        
            $healthycopies = @($copies | Where-Object { (($_.Status -eq "Mounted") -or ($_.Status -eq "Healthy")) }).Count
            $databaseObj | Add-Member NoteProperty -Name "Healthy Copies" -Value $healthycopies -Force
            
            $unhealthycopies = @($copies | Where-Object { (($_.Status -ne "Mounted") -and ($_.Status -ne "Healthy")) }).Count
            $databaseObj | Add-Member NoteProperty -Name "Unhealthy Copies" -Value $unhealthycopies -Force

            $healthyqueues = @($copies | Where-Object { (($_."Copy Queue" -lt $replqueuewarning) -and (($_."Replay Queue" -lt $replqueuewarning)) -and ($_."Replay Lagged" -eq $false)) }).Count
            $databaseObj | Add-Member NoteProperty -Name "Healthy Queues" -Value $healthyqueues -Force

            $unhealthyqueues = @($copies | Where-Object { (($_."Copy Queue" -ge $replqueuewarning) -or (($_."Replay Queue" -ge $replqueuewarning) -and ($_."Replay Lagged" -eq $false))) }).Count
            $databaseObj | Add-Member NoteProperty -Name "Unhealthy Queues" -Value $unhealthyqueues -Force

            $laggedqueues = @($copies | Where-Object { ($_."Replay Lagged" -eq $true) -or ($_."Truncation Lagged" -eq $true) }).Count
            $databaseObj | Add-Member NoteProperty -Name "Lagged Queues" -Value $laggedqueues -Force

            $healthyindexes = @($copies | Where-Object { ($_."Content Index" -eq "Healthy" -or $_."Content Index" -eq "Disabled" -or $_."Content Index" -eq "AutoSuspended") }).Count
            $databaseObj | Add-Member NoteProperty -Name "Healthy Indexes" -Value $healthyindexes -Force
            
            $unhealthyindexes = @($copies | Where-Object { ($_."Content Index" -ne "Healthy" -and $_."Content Index" -ne "Disabled" -and $_."Content Index" -ne "AutoSuspended") }).Count
            $databaseObj | Add-Member NoteProperty -Name "Unhealthy Indexes" -Value $unhealthyindexes -Force
            
            $dagdatabaseSummary += $databaseObj
        }

        
        # Get Test-Replication Health results for each DAG member
        foreach ($dagmember in $dagmembers)
        {
            $replicationhealth = $null

            $replicationhealthitems = @{
                                        ClusterService = $null
                                        ReplayService = $null
                                        ActiveManager = $null
                                        TasksRpcListener = $null
                                        TcpListener = $null
                                        ServerLocatorService = $null
                                        DagMembersUp = $null
                                        ClusterNetwork = $null
                                        QuorumGroup = $null
                                        FileShareQuorum = $null
                                        DatabaseRedundancy = $null
                                        DatabaseAvailability = $null
                                        DBCopySuspended = $null
                                        DBCopyFailed = $null
                                        DBInitializing = $null
                                        DBDisconnected = $null
                                        DBLogCopyKeepingUp = $null
                                        DBLogReplayKeepingUp = $null
                                        }

            $memberObj = New-Object PSObject -Property $replicationhealthitems
            $memberObj | Add-Member NoteProperty -Name "Server" -Value $($dagmember.Name)
        
            $tmpstring = "---- Checking replication health for $($dagmember.Name)"
            Write-Verbose $tmpstring
            if ($Log) {Write-Logfile $tmpstring}
            
            try
            {
                $replicationhealth = Test-ReplicationHealth -Identity $dagmember.Name -ErrorAction Stop
            }
            catch
            {
                Write-Warning "Failed to test replication health for $($dagmember.Name): $($_.Exception.Message)"
                if ($Log) {Write-Logfile "Failed replication health: $($_.Exception.Message)"}
            }
            
            if ($replicationhealth)
            {
                foreach ($healthitem in $replicationhealth)
                {
                    if ($null -eq $($healthitem.Result))
                    {
                        $healthitemresult = "n/a"
                    }
                    else
                    {
                        $healthitemresult = "$($healthitem.Result)"
                    }
                    $tmpstring = "$($healthitem.Check) $healthitemresult"
                    Write-Verbose $tmpstring
                    if ($Log) {Write-Logfile $tmpstring}
                    $memberObj | Add-Member NoteProperty -Name $($healthitem.Check) -Value $healthitemresult -Force
                }
            }
            $dagmemberReport += $memberObj
        }


        
        # Generate the HTML from the DAG health checks
        if ($SendEmail -or $ReportFile)
        {
        
            ####Begin Summary Table HTML
            $dagdatabaseSummaryHtml = $null
            $htmltableheader = "<p>
                            <table>
                            <tr>
                            <th>Database</th>
                            <th>Mounted on</th>
                            <th>Preference</th>
                            <th>Total Copies</th>
                            <th>Healthy Copies</th>
                            <th>Unhealthy Copies</th>
                            <th>Healthy Queues</th>
                            <th>Unhealthy Queues</th>
                            <th>Lagged Queues</th>
                            <th>Healthy Indexes</th>
                            <th>Unhealthy Indexes</th>
                            </tr>"

            $dagdatabaseSummaryHtml += $htmltableheader
            
            # Summary table rows
            foreach ($line in $dagdatabaseSummary)
            {
                $htmltablerow = "<tr>"
                $htmltablerow += "<td><strong>$($line.Database)</strong></td>"
                
                switch ($($line."Mounted on"))
                {
                    "Unknown" {
                        $htmltablerow += "<td class=""warn"">$($line."Mounted on")</td>"
                        $dagsummary += "$($line.Database) - $string61"
                        }
                    default { $htmltablerow += "<td>$($line."Mounted on")</td>" }
                }
                
                if ($($line.Preference) -gt 1)
                {
                    $htmltablerow += "<td class=""warn"">$($line.Preference)</td>"
                    $dagsummary += "$($line.Database) - $string62 $($line.Preference)"
                }
                else
                {
                    $htmltablerow += "<td class=""pass"">$($line.Preference)</td>"
                }
                
                $htmltablerow += "<td>$($line."Total Copies")</td>"
                
                switch ($($line."Healthy Copies"))
                {    
                    0 {$htmltablerow += "<td class=""fail"">$($line."Healthy Copies")</td>"}
                    1 {
                        if ($($line."Total Copies") -eq $($line."Healthy Copies"))
                        {
                            $htmltablerow += "<td class=""info"">$($line."Healthy Copies")</td>"
                        }
                        else
                        {
                            $htmltablerow += "<td class=""warn"">$($line."Healthy Copies")</td>"
                        }
                      }
                    default {$htmltablerow += "<td class=""pass"">$($line."Healthy Copies")</td>"}
                }


                switch ($($line."Unhealthy Copies"))
                {
                    0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Copies")</td>" }
                    1 {
                        $htmltablerow += "<td class=""warn"">$($line."Unhealthy Copies")</td>"
                        $dagsummary += "$($line.Database) - $string63 $($line."Unhealthy Copies") $string65 $($line."Total Copies") $string66"
                        }
                    default {
                        $htmltablerow += "<td class=""fail"">$($line."Unhealthy Copies")</td>"
                        $dagsummary += "$($line.Database) - $string63 $($line."Unhealthy Copies") $string65 $($line."Total Copies") $string66"
                        }
                }

                if ($($line."Total Copies") -eq ($($line."Healthy Queues") + $($line."Lagged Queues")))
                {
                    $htmltablerow += "<td class=""pass"">$($line."Healthy Queues")</td>"
                }
                else
                {
                    $dagsummary += "$($line.Database) - $string64 $($line."Healthy Queues") $string65 $($line."Total Copies") $string66"
                    switch ($($line."Healthy Queues"))
                    {
                        0 { $htmltablerow += "<td class=""fail"">$($line."Healthy Queues")</td>" }
                        default { $htmltablerow += "<td class=""warn"">$($line."Healthy Queues")</td>" }
                    }
                }
                
                if ($($line."Total Queues") -eq $($line."Unhealthy Queues"))
                {
                    $htmltablerow += "<td class=""fail"">$($line."Unhealthy Queues")</td>"
                }
                else
                {
                    switch ($($line."Unhealthy Queues"))
                    {
                        0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Queues")</td>" }
                        default { $htmltablerow += "<td class=""warn"">$($line."Unhealthy Queues")</td>" }
                    }
                }
                
                switch ($($line."Lagged Queues"))
                {
                    0 { $htmltablerow += "<td>$($line."Lagged Queues")</td>" }
                    default { $htmltablerow += "<td class=""info"">$($line."Lagged Queues")</td>" }
                }
                
                if ($($line."Total Copies") -eq $($line."Healthy Indexes"))
                {
                    $htmltablerow += "<td class=""pass"">$($line."Healthy Indexes")</td>"
                }
                else
                {
                    $dagsummary += "$($line.Database) - $string67 $($line."Unhealthy Indexes") $string65 $($line."Total Copies") $string66"
                    switch ($($line."Healthy Indexes"))
                    {
                        0 { $htmltablerow += "<td class=""fail"">$($line."Healthy Indexes")</td>" }
                        default { $htmltablerow += "<td class=""warn"">$($line."Healthy Indexes")</td>" }
                    }
                }
                
                if ($($line."Total Copies") -eq $($line."Unhealthy Indexes"))
                {
                    $htmltablerow += "<td class=""fail"">$($line."Unhealthy Indexes")</td>"
                }
                else
                {
                    switch ($($line."Unhealthy Indexes"))
                    {
                        0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Indexes")</td>" }
                        default { $htmltablerow += "<td class=""warn"">$($line."Unhealthy Indexes")</td>" }
                    }
                }
                
                $htmltablerow += "</tr>"
                $dagdatabaseSummaryHtml += $htmltablerow
            }
            $dagdatabaseSummaryHtml += "</table></p>"
            ####End Summary Table HTML


            ####Begin Detail Table HTML
            $databasedetailsHtml = $null
            $htmltableheader = "<p>
                                <table>
                                <tr>
                                <th>Database Copy</th>
                                <th>Database Name</th>
                                <th>Mailbox Server</th>
                                <th>Activation Preference</th>
                                <th>Status</th>
                                <th>Copy Queue</th>
                                <th>Replay Queue</th>
                                <th>Replay Lagged</th>
                                <th>Truncation Lagged</th>
                                <th>Content Index</th>
                                </tr>"

            $databasedetailsHtml += $htmltableheader
            
            foreach ($line in $dagdbcopyReport)
            {
                $htmltablerow = "<tr>"
                $htmltablerow += "<td><strong>$($line."Database Copy")</strong></td>"
                $htmltablerow += "<td>$($line."Database Name")</td>"
                $htmltablerow += "<td>$($line."Mailbox Server")</td>"
                $htmltablerow += "<td>$($line."Activation Preference")</td>"
                
                Switch ($($line."Status"))
                {
                    "Healthy" { $htmltablerow += "<td class=""pass"">$($line."Status")</td>" }
                    "Mounted" { $htmltablerow += "<td class=""pass"">$($line."Status")</td>" }
                    "Failed" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
                    "FailedAndSuspended" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
                    "ServiceDown" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
                    "Dismounted" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
                    default { $htmltablerow += "<td class=""warn"">$($line."Status")</td>" }
                }
                
                if ($($line."Copy Queue") -lt $replqueuewarning)
                {
                    $htmltablerow += "<td class=""pass"">$($line."Copy Queue")</td>"
                }
                else
                {
                    $htmltablerow += "<td class=""warn"">$($line."Copy Queue")</td>"
                }
                
                if (($($line."Replay Queue") -lt $replqueuewarning) -or ($($line."Replay Lagged") -eq $true))
                {
                    $htmltablerow += "<td class=""pass"">$($line."Replay Queue")</td>"
                }
                else
                {
                    $htmltablerow += "<td class=""warn"">$($line."Replay Queue")</td>"
                }

                Switch ($($line."Replay Lagged"))
                {
                    $true { $htmltablerow += "<td class=""info"">$($line."Replay Lagged")</td>" }
                    default { $htmltablerow += "<td>$($line."Replay Lagged")</td>" }
                }

                Switch ($($line."Truncation Lagged"))
                {
                    $true { $htmltablerow += "<td class=""info"">$($line."Truncation Lagged")</td>" }
                    default { $htmltablerow += "<td>$($line."Truncation Lagged")</td>" }
                }
                
                Switch ($($line."Content Index"))
                {
                    "Healthy" { $htmltablerow += "<td class=""pass"">$($line."Content Index")</td>" }
                    "Disabled" { $htmltablerow += "<td class=""info"">$($line."Content Index")</td>" }
                    default { $htmltablerow += "<td class=""warn"">$($line."Content Index")</td>" }
                }
                
                $htmltablerow += "</tr>"
                $databasedetailsHtml += $htmltablerow
            }
            $databasedetailsHtml += "</table></p>"
            ####End Detail Table HTML

            
            ####Begin Member Table HTML
            $dagmemberHtml = $null
            $htmltableheader = "<p>
                                <table>
                                <tr>
                                <th>Server</th>
                                <th>Cluster Service</th>
                                <th>Replay Service</th>
                                <th>Active Manager</th>
                                <th>Tasks RPC Listener</th>
                                <th>TCP Listener</th>
                                <th>Server Locator Service</th>
                                <th>DAG Members Up</th>
                                <th>Cluster Network</th>
                                <th>Quorum Group</th>
                                <th>File Share Quorum</th>
                                <th>Database Redundancy</th>
                                <th>Database Availability</th>
                                <th>DB Copy Suspended</th>
                                <th>DB Copy Failed</th>
                                <th>DB Initializing</th>
                                <th>DB Disconnected</th>
                                <th>DB Log Copy Keeping Up</th>
                                <th>DB Log Replay Keeping Up</th>
                                </tr>"
            
            $dagmemberHtml += $htmltableheader
            
            foreach ($line in $dagmemberReport)
            {
                $htmltablerow = "<tr>"
                $htmltablerow += "<td><strong>$($line."Server")</strong></td>"
                $htmltablerow += (New-DAGMemberHTMLTableCell "ClusterService")
                $htmltablerow += (New-DAGMemberHTMLTableCell "ReplayService")
                $htmltablerow += (New-DAGMemberHTMLTableCell "ActiveManager")
                $htmltablerow += (New-DAGMemberHTMLTableCell "TasksRPCListener")
                $htmltablerow += (New-DAGMemberHTMLTableCell "TCPListener")
                $htmltablerow += (New-DAGMemberHTMLTableCell "ServerLocatorService")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DAGMembersUp")
                $htmltablerow += (New-DAGMemberHTMLTableCell "ClusterNetwork")
                $htmltablerow += (New-DAGMemberHTMLTableCell "QuorumGroup")
                $htmltablerow += (New-DAGMemberHTMLTableCell "FileShareQuorum")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DatabaseRedundancy")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DatabaseAvailability")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DBCopySuspended")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DBCopyFailed")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DBInitializing")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DBDisconnected")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DBLogCopyKeepingUp")
                $htmltablerow += (New-DAGMemberHTMLTableCell "DBLogReplayKeepingUp")
                $htmltablerow += "</tr>"
                $dagmemberHtml += $htmltablerow
            }
            $dagmemberHtml += "</table></p>"
        }

        
        if ($SendEmail -or $ReportFile)
        {
            $dagreporthtml = $dagsummaryintro + $dagdatabaseSummaryHtml + $dagdetailintro + $databasedetailsHtml + $dagmemberintro + $dagmemberHtml
            $dagreportbody += $dagreporthtml
        }
        
    }
}
else
{
    $tmpstring = "No DAGs found"
    if ($Log) {Write-LogFile $tmpstring}
    Write-Verbose $tmpstring
    $dagreporthtml = "<p>No database availability groups found.</p>"
}
### End DAG Health Report


Write-Host $string16
### Begin report generation
if ($ReportMode -or $SendEmail)
{
    $reportime = Get-Date

    # HTML head with improved styling
    $htmlhead="<html>
                <style>
                BODY{font-family: Segoe UI, Arial, sans-serif; font-size: 9pt; margin: 10px;}
                H1{font-size: 18px; color: #333;}
                H2{font-size: 15px; color: #444;}
                H3{font-size: 13px; color: #555;}
                TABLE{border: 1px solid #ccc; border-collapse: collapse; font-size: 8pt; width: 100%;}
                TH{border: 1px solid #ccc; background: #e8e8e8; padding: 6px 8px; color: #333; text-align: left;}
                TD{border: 1px solid #ccc; padding: 5px 8px;}
                td.pass{background: #7FFF00;}
                td.warn{background: #FFE600;}
                td.fail{background: #FF0000; color: #ffffff;}
                td.info{background: #85D4FF;}
                </style>
                <body>
                <h1 align=""center"">Exchange Server Health Check Report</h1>
                <h3 align=""center"">Generated: $reportime</h3>"


    # Server summary section
    if ($($serversummary.count) -gt 0)
    {
        $alerts = $true
        $serversummaryhtml = "<h3>Exchange Server Health Check Summary</h3>
                        <p>The following server errors and warnings were detected.</p>
                        <p><ul>"
        foreach ($reportline in $serversummary)
        {
            $serversummaryhtml +="<li>$reportline</li>"
        }
        $serversummaryhtml += "</ul></p>"
    }
    else
    {
        $serversummaryhtml = "<h3>Exchange Server Health Check Summary</h3>
                        <p>No Exchange server health errors or warnings.</p>"
    }
    
    # DAG summary section
    if ($($dagsummary.count) -gt 0)
    {
        $alerts = $true
        $dagsummaryhtml = "<h3>Database Availability Group Health Check Summary</h3>
                        <p>The following DAG errors and warnings were detected.</p>
                        <p><ul>"
        foreach ($reportline in $dagsummary)
        {
            $dagsummaryhtml +="<li>$reportline</li>"
        }
        $dagsummaryhtml += "</ul></p>"
    }
    else
    {
        $dagsummaryhtml = "<h3>Database Availability Group Health Check Summary</h3>
                        <p>No Exchange DAG errors or warnings.</p>"
    }


    # Exchange Server Health Report Table (no UM column, no PF DB column)
    $htmltableheader = "<h3>Exchange Server Health</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Server</th>
                        <th>Site</th>
                        <th>Roles</th>
                        <th>Version</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime (hrs)</th>
                        <th>Client Access Services</th>
                        <th>Transport Services</th>
                        <th>Mailbox Services</th>
                        <th>Transport Queue</th>
                        <th>MB DBs Mounted</th>
                        <th>MAPI Test</th>
                        <th>Mail Flow Test</th>
                        </tr>"

    $serverhealthhtmltable = $htmltableheader                    
                        
    foreach ($reportline in $report)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.server)</td>"
        $htmltablerow += "<td>$($reportline.site)</td>"
        $htmltablerow += "<td>$($reportline.roles)</td>"
        $htmltablerow += "<td>$($reportline.version)</td>"                    
        $htmltablerow += (New-ServerHealthHTMLTableCell "dns")
        $htmltablerow += (New-ServerHealthHTMLTableCell "ping")
        
        if ($($reportline."uptime (hrs)") -eq "Access Denied")
        {
            $htmltablerow += "<td class=""warn"">Access Denied</td>"        
        }
        elseif ($($reportline."uptime (hrs)") -eq $string17)
        {
            $htmltablerow += "<td class=""warn"">$string17</td>"
        }
        else
        {
            $hours = [int]$($reportline."uptime (hrs)")
            if ($hours -le 24)
            {
                $htmltablerow += "<td class=""warn"">$hours</td>"
            }
            else
            {
                $htmltablerow += "<td class=""pass"">$hours</td>"
            }
        }

        $htmltablerow += (New-ServerHealthHTMLTableCell "Client Access Server Role Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hub Transport Server Role Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Mailbox Server Role Services")

        
        # Transport Queue with color coding
        if ($($reportline."Transport Queue") -match "Pass")
        {
            $htmltablerow += "<td class=""pass"">$($reportline."Transport Queue")</td>"
        }
        elseif ($($reportline."Transport Queue") -match "Warn")
        {
            $htmltablerow += "<td class=""warn"">$($reportline."Transport Queue")</td>"
        }
        elseif ($($reportline."Transport Queue") -match "Fail")
        {
            $htmltablerow += "<td class=""fail"">$($reportline."Transport Queue")</td>"
        }
        elseif ($($reportline."Transport Queue") -eq "n/a")
        {
            $htmltablerow += "<td>$($reportline."Transport Queue")</td>"
        }
        else
        {
            $htmltablerow += "<td class=""warn"">$($reportline."Transport Queue")</td>"
        }

        $htmltablerow += (New-ServerHealthHTMLTableCell "MB DBs Mounted")
        $htmltablerow += (New-ServerHealthHTMLTableCell "MAPI Test")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Mail Flow Test")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    $serverhealthhtmltable = $serverhealthhtmltable + "</table></p>"

    $htmltail = "</body></html>"

    $htmlreport = $htmlhead + $serversummaryhtml + $dagsummaryhtml + $serverhealthhtmltable + $dagreportbody + $htmltail
    
    if ($ReportMode -or $ReportFile)
    {
        $htmlreport | Out-File $ReportFile -Encoding UTF8
    }

    if ($SendEmail)
    {
        if ($alerts -eq $false -and $AlertsOnly -eq $true)
        {
            Write-Host $string19
            if ($Log) {Write-Logfile $string19}
        }
        else
        {
            Write-Host $string14
            Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
        }
    }
}
### End report generation

Write-Host $string15
if ($Log) {Write-Logfile $string15}
