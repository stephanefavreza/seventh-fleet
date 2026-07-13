<#
.SYNOPSIS
    Entra ID Sign-In Triage Tool - Investigate sign-in issues with full diagnostics.

.DESCRIPTION
    Pulls sign-in logs from Microsoft Graph for a user and/or application,
    decodes AADSTS error codes into plain meanings with remediation hints,
    runs anomaly detectors (geo-anomalies, impossible travel, burst logins,
    device/OS shifts, unusual hours, MFA failures), and generates a self-contained
    HTML dashboard plus a color-coded console triage summary.

.PARAMETER UserPrincipalName
    The UPN of the user to investigate (e.g. john.doe@contoso.com).

.PARAMETER AppId
    The Application (client) ID to filter sign-in logs.

.PARAMETER AppDisplayName
    The application display name to filter sign-in logs.

.PARAMETER HoursBack
    How many hours back to pull logs. Default: 72.

.PARAMETER OutputPath
    Directory where the HTML report will be saved. Default: script directory.

.PARAMETER Top
    Maximum number of sign-in records to retrieve. Default: 500.

.EXAMPLE
    .\Invoke-EntraSignInTriage.ps1 -UserPrincipalName "user@contoso.com" -HoursBack 48

.EXAMPLE
    .\Invoke-EntraSignInTriage.ps1 -AppId "00000000-0000-0000-0000-000000000000" -HoursBack 24

.LINK
    https://github.com/stephanefavreza/seventh-fleet

.NOTES
    Version:     1.0.0
    Author:      Community Contributors
    Requires:    Microsoft.Graph.Authentication module
    Permissions: AuditLog.Read.All, Directory.Read.All
    License:     MIT

    Copyright (c) 2025 Contributors

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    DISCLAIMER: This script is provided "as is" without warranty of any kind.
    Use at your own risk. Always test in a non-production environment first.
    The authors are not responsible for any damage or data loss resulting from
    the use of this script.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$AppId,

    [Parameter()]
    [string]$AppDisplayName,

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 72,

    [Parameter()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [ValidateRange(1, 5000)]
    [int]$Top = 500
)

#region ─── Prerequisites ───────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web  # For HtmlEncode in report generation

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Error "Module 'Microsoft.Graph.Authentication' is required. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    return
}

# Connect if not already connected
$context = Get-MgContext
if (-not $context) {
    Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" -NoWelcome
}
#endregion

#region ─── AADSTS Error Code Dictionary ────────────────────────────────────────
$AADSTSErrors = @{
    "50001" = @{ Meaning = "Resource not found in tenant"; Remediation = "Ensure the app is registered in the correct tenant and the resource identifier is correct." }
    "50011" = @{ Meaning = "Reply URL mismatch"; Remediation = "Update the redirect URI in the app registration to match the one sent in the request." }
    "50012" = @{ Meaning = "Authentication failed - invalid credentials"; Remediation = "Verify the user's password is correct. Check for recent password changes." }
    "50013" = @{ Meaning = "Assertion token is invalid (expired or wrong issuer)"; Remediation = "Ensure the token has not expired and the issuer matches the expected authority." }
    "50014" = @{ Meaning = "Guest user passthrough not allowed"; Remediation = "Check cross-tenant access settings and guest user policies." }
    "50020" = @{ Meaning = "User account from external identity provider does not exist in tenant"; Remediation = "Invite the user as a guest or check federation settings." }
    "50034" = @{ Meaning = "User account does not exist in directory"; Remediation = "Verify the UPN is correct. The account may have been deleted or never provisioned." }
    "50053" = @{ Meaning = "Account locked - too many sign-in attempts with incorrect password"; Remediation = "Wait for the lockout to expire or reset via SSPR/admin. Review for brute-force attacks." }
    "50055" = @{ Meaning = "Password expired"; Remediation = "The user must change their password. Enable SSPR or have an admin reset it." }
    "50056" = @{ Meaning = "Invalid or null password"; Remediation = "The user has no password credential set. Reset or register a password." }
    "50057" = @{ Meaning = "User account is disabled"; Remediation = "Re-enable the account in Entra ID or on-prem AD if synced." }
    "50058" = @{ Meaning = "Silent sign-in failed - user must sign in interactively"; Remediation = "Expected in SSO flows; prompt user for interactive sign-in." }
    "50059" = @{ Meaning = "Tenant not found (tenant may have been deleted)"; Remediation = "Verify the tenant ID/domain. The organization may no longer exist." }
    "50061" = @{ Meaning = "Sign-out request invalid"; Remediation = "Check the logout URI configuration in the app registration." }
    "50064" = @{ Meaning = "Credential authentication failed"; Remediation = "Verify username/password combination. Check for typos or password sync issues." }
    "50072" = @{ Meaning = "User must enroll for MFA (strong auth required)"; Remediation = "User needs to register MFA at https://aka.ms/mfasetup." }
    "50074" = @{ Meaning = "MFA challenge required but not completed"; Remediation = "User did not complete MFA. Check phone/authenticator availability." }
    "50076" = @{ Meaning = "MFA required by policy (Conditional Access)"; Remediation = "A CA policy requires MFA. Ensure user has MFA methods registered." }
    "50078" = @{ Meaning = "MFA claim in token expired"; Remediation = "User must re-authenticate with MFA. Session lifetime may be too short." }
    "50079" = @{ Meaning = "User must enroll for MFA (enforced per-user)"; Remediation = "Admin has enforced MFA. User must register at https://aka.ms/mfasetup." }
    "50097" = @{ Meaning = "Device authentication required"; Remediation = "Device must be Entra ID joined/registered or compliant." }
    "50105" = @{ Meaning = "User not assigned to a role for the application"; Remediation = "Assign the user or a group they belong to in the Enterprise App > Users and groups." }
    "50126" = @{ Meaning = "Invalid username or password"; Remediation = "Verify credentials. Check password hash sync status if using hybrid identity." }
    "50128" = @{ Meaning = "Invalid domain name - tenant not found"; Remediation = "The domain in the request is not recognized. Verify tenant domain configuration." }
    "50129" = @{ Meaning = "Device not workplace joined (device registration required)"; Remediation = "Register or join the device to Entra ID. Check CA policy requirements." }
    "50131" = @{ Meaning = "Conditional Access - device not compliant or not registered"; Remediation = "Ensure device meets compliance requirements in Intune. Re-register if needed." }
    "50132" = @{ Meaning = "Session revoked (password change or admin action)"; Remediation = "User must re-authenticate. This is expected after password/session revocation." }
    "50133" = @{ Meaning = "Session expired or recent password change invalidated token"; Remediation = "Re-authenticate. Check Continuous Access Evaluation (CAE) settings." }
    "50140" = @{ Meaning = "Keep Me Signed In (KMSI) interrupt"; Remediation = "This is informational - user was prompted to stay signed in." }
    "50143" = @{ Meaning = "Session mismatch - different user expected for resource tenant"; Remediation = "Clear browser cookies/sessions and retry with correct account." }
    "50144" = @{ Meaning = "User's Active Directory password has expired"; Remediation = "Reset password in on-prem AD and wait for sync (or trigger delta sync)." }
    "50158" = @{ Meaning = "External security challenge not satisfied (external MFA)"; Remediation = "Check external MFA provider (e.g., Duo, RSA). Verify it is reachable." }
    "50163" = @{ Meaning = "Session must be re-established (prompt=login in request)"; Remediation = "Expected behavior when app sends prompt=login. User must sign in again." }
    "50166" = @{ Meaning = "External claim provider returned an error"; Remediation = "Check custom claims provider configuration and endpoint health." }
    "50173" = @{ Meaning = "Fresh auth token needed - session cookie invalid"; Remediation = "Clear browser cache/cookies and sign in again." }
    "50177" = @{ Meaning = "External challenge not supported for passthrough users"; Remediation = "Review conditional access policies for passthrough authentication scenarios." }
    "50196" = @{ Meaning = "Client detected a loop (too many redirects)"; Remediation = "Clear browser cookies. Check for CA policy conflicts causing redirect loops." }
    "51000" = @{ Meaning = "Network policy error (wstrust endpoint issue)"; Remediation = "Check AD FS health and DNS resolution for federation endpoints." }
    "51001" = @{ Meaning = "Domain hint missing for on-premises federated identity"; Remediation = "Include domain_hint parameter or verify home realm discovery settings." }
    "51004" = @{ Meaning = "User account doesn't exist in directory (misspelled username)"; Remediation = "Verify UPN spelling. Check if the account exists in the expected tenant." }
    "52004" = @{ Meaning = "User has not provided consent for LinkedIn integration"; Remediation = "User must consent or admin can grant consent for LinkedIn account access." }
    "53000" = @{ Meaning = "Conditional Access - device not compliant (blocked)"; Remediation = "Device must be compliant in Intune. Check compliance policies and device state." }
    "53001" = @{ Meaning = "Conditional Access - blocked by policy (not compliant/not joined)"; Remediation = "Review which CA policy is blocking. Check device/location/risk conditions." }
    "53003" = @{ Meaning = "Conditional Access - access blocked by policy"; Remediation = "Identify the blocking CA policy in Sign-in logs > CA tab. Adjust grant controls or exclusions." }
    "53004" = @{ Meaning = "Conditional Access - must accept Terms of Use"; Remediation = "User must accept the Terms of Use. Check ToU policy assignment." }
    "53005" = @{ Meaning = "Application does not meet Conditional Access requirements"; Remediation = "Check if the app supports required controls (e.g., app protection policy, approved client)." }
    "54000" = @{ Meaning = "Consent required but not granted"; Remediation = "User or admin must grant consent. Check if admin consent workflow is enabled." }
    "65001" = @{ Meaning = "Application does not have access to resource (consent not granted)"; Remediation = "Grant admin consent via Portal > Enterprise App > Permissions, or user consent if allowed." }
    "65004" = @{ Meaning = "User declined consent"; Remediation = "User refused consent. Admin can grant on behalf via admin consent flow." }
    "65005" = @{ Meaning = "Application misconfigured - invalid resource access list"; Remediation = "Review API permissions in app registration. Remove invalid or conflicting permissions." }
    "70000" = @{ Meaning = "Invalid grant - authentication code or refresh token expired/revoked"; Remediation = "The token is no longer valid. Re-authenticate from the beginning." }
    "70001" = @{ Meaning = "Application not found in tenant (app deleted or not consented)"; Remediation = "Re-register the application or grant admin consent for multi-tenant apps." }
    "70008" = @{ Meaning = "Authorization code or refresh token expired"; Remediation = "Re-authenticate. Codes are valid for 10 min; refresh tokens for up to 90 days." }
    "70011" = @{ Meaning = "Invalid scope - permission not recognized"; Remediation = "Check the scope/permission string. Use the format: api://<id>/<permission> or well-known scopes." }
    "70016" = @{ Meaning = "Device code flow - authorization pending"; Remediation = "User has not yet completed device code flow. Wait or retry the user prompt." }
    "70018" = @{ Meaning = "Device code expired"; Remediation = "The device code has expired (15 min default). Restart the device code flow." }
    "70019" = @{ Meaning = "Verification code expired"; Remediation = "Request a new verification code and complete the flow within the time limit." }
    "70043" = @{ Meaning = "Refresh token expired due to inactivity (sign-in frequency)"; Remediation = "User must sign in again. CA sign-in frequency policy triggered revocation." }
    "75003" = @{ Meaning = "SAML binding error - unsigned request sent to endpoint requiring signing"; Remediation = "Configure the application to sign SAML requests or update metadata." }
    "75005" = @{ Meaning = "SAML request malformed"; Remediation = "Validate the SAML request XML. Check for encoding/formatting issues." }
    "75008" = @{ Meaning = "SAML request denied - the request was unexpected"; Remediation = "Request doesn't match expected SAML flow. Verify SP-initiated vs IdP-initiated config." }
    "75011" = @{ Meaning = "SAML authentication method mismatch"; Remediation = "Auth method in SAML assertion doesn't match what's requested. Review auth context." }
    "75016" = @{ Meaning = "SAML2 AuthnRequest NameIdPolicy mismatch"; Remediation = "NameID format in the request doesn't match app configuration. Align both sides." }
    "80001" = @{ Meaning = "Authentication Agent unable to connect to Active Directory"; Remediation = "Check pass-through authentication agent health and AD connectivity." }
    "80007" = @{ Meaning = "Authentication Agent unable to validate password"; Remediation = "Check AD account lockout, connectivity, and PTA agent logs." }
    "80010" = @{ Meaning = "Authentication Agent unable to decrypt password"; Remediation = "PTA agent registration may be corrupted. Re-register the agent." }
    "80012" = @{ Meaning = "User signed in outside allowed logon hours"; Remediation = "Check AD logon hours restriction for the user account." }
    "80014" = @{ Meaning = "Validation response max elapsed time exceeded"; Remediation = "PTA agent is too slow responding. Check network latency and AD health." }
    "81004" = @{ Meaning = "Kerberos authentication failed - ticket invalid"; Remediation = "Check Seamless SSO configuration. Verify AZUREADSSOACC computer account and its password." }
    "81006" = @{ Meaning = "Kerberos ticket expired or invalid"; Remediation = "Ensure machine clock is synced. Clear Kerberos ticket cache (klist purge)." }
    "81007" = @{ Meaning = "Tenant not enabled for Seamless SSO"; Remediation = "Enable Seamless SSO in Entra Connect settings." }
    "81009" = @{ Meaning = "Cannot validate Kerberos ticket - machine account password stale"; Remediation = "Roll the AZUREADSSOACC password using Update-AzureADSSOForest." }
    "81010" = @{ Meaning = "Seamless SSO failed - user's Kerberos ticket expired or invalid"; Remediation = "User should lock/unlock workstation or run klist purge." }
    "81012" = @{ Meaning = "User trying to sign in is different from user logged into device"; Remediation = "Sign out of device or use InPrivate/incognito browser session." }
    "90010" = @{ Meaning = "Request not supported (unsupported method/protocol)"; Remediation = "Check the request method and protocol version. Update application code." }
    "90014" = @{ Meaning = "Required field missing in request (MFA-related)"; Remediation = "Check for missing parameters in the authentication request." }
    "90072" = @{ Meaning = "User needs to enroll for MFA (external tenant)"; Remediation = "Register MFA in the home tenant before accessing the resource." }
    "90094" = @{ Meaning = "Admin consent required for this application"; Remediation = "An admin must grant tenant-wide consent for this application's permissions." }
    "90095" = @{ Meaning = "Admin consent required (missing delegation)"; Remediation = "Admin must grant consent. Check admin consent workflow in Enterprise apps." }
    "120000" = @{ Meaning = "Password change required (age/policy)"; Remediation = "User must change password at next login. Enable SSPR for self-service." }
    "120002" = @{ Meaning = "Passkey/FIDO2 error or user cancelled"; Remediation = "User cancelled the security key prompt, or the key is not recognized. Re-try or re-register." }
    "130004" = @{ Meaning = "Non-DRS device used when device authentication is required"; Remediation = "Device must be registered in DRS (Device Registration Service). Entra join or register it." }
    "130005" = @{ Meaning = "Device must be managed (MDM/MAM required)"; Remediation = "Enroll device in Intune or another MDM. Check Conditional Access requirements." }
    "135010" = @{ Meaning = "Key not found for token signing"; Remediation = "Token signing key rotation issue. Check app registration certificates/keys." }
    "135011" = @{ Meaning = "Device used during authentication is disabled"; Remediation = "Device object is disabled in Entra ID. Re-enable it or re-register." }
    "140000" = @{ Meaning = "Refresh token revoked (user session revoked by admin)"; Remediation = "Expected after Revoke Sessions. User must sign in fresh." }
    "165900" = @{ Meaning = "Cross-origin request denied (CORS)"; Remediation = "Add the origin to the app registration's redirect URIs or SPA settings." }
    "220000" = @{ Meaning = "Cross-tenant access blocked by inbound/outbound policy"; Remediation = "Review cross-tenant access settings. Add trust or allow the external tenant." }
    "500011" = @{ Meaning = "Resource principal not found in tenant"; Remediation = "The service principal for the resource doesn't exist. Run admin consent or create it." }
    "500021" = @{ Meaning = "Access denied by tenant restriction policy"; Remediation = "Tenant restrictions are blocking access. Review the policy or add exceptions." }
    "500121" = @{ Meaning = "MFA authentication failed during strong auth request"; Remediation = "MFA was attempted but failed. Check authenticator/phone. Re-register MFA methods if needed." }
    "500133" = @{ Meaning = "Token not within its valid time range"; Remediation = "Clock skew detected. Sync machine time. Or token has expired - re-authenticate." }
    "530003" = @{ Meaning = "Device not in required state (not compliant, not managed)"; Remediation = "Check Intune compliance. Device might need re-enrollment or policy refresh." }
    "530021" = @{ Meaning = "Application does not meet Conditional Access approved app requirements"; Remediation = "Use an approved client app as required by the CA policy. Check the list of approved apps." }
    "530032" = @{ Meaning = "Blocked by security defaults (legacy auth blocked)"; Remediation = "Disable legacy authentication protocols. Use modern auth clients." }
    "700003" = @{ Meaning = "Device object disabled"; Remediation = "Device is disabled in Entra ID. Re-enable or re-register the device." }
    "700016" = @{ Meaning = "Application not found in tenant (client_id mismatch)"; Remediation = "Verify the client_id. Register the app in the correct tenant or grant consent." }
    "700025" = @{ Meaning = "Client is public - client secret provided unexpectedly"; Remediation = "The app is configured as a public client but credentials were sent. Adjust app manifest." }
    "700027" = @{ Meaning = "Client assertion contains invalid signature"; Remediation = "Check the certificate used for client assertion. It may be expired or mismatched." }
    "7000112" = @{ Meaning = "Application is disabled"; Remediation = "The enterprise application is disabled. Enable it in Enterprise Apps > Properties." }
    "7000114" = @{ Meaning = "Application not allowed to make on-behalf-of calls"; Remediation = "Check OBO permissions and pre-authorization settings for the middle-tier app." }
    "7000215" = @{ Meaning = "Invalid client secret provided"; Remediation = "The secret is wrong or expired. Generate a new client secret in app registration." }
    "7000218" = @{ Meaning = "Request body must contain client_assertion or client_secret"; Remediation = "Add client credentials to the token request. Check app type (confidential vs public)." }
    "7000222" = @{ Meaning = "Client secret expired"; Remediation = "The secret has expired. Create a new one in Azure Portal > App Registration > Certificates & secrets." }
    "9002313" = @{ Meaning = "Request blocked due to suspicious activity (risk-based)"; Remediation = "Identity Protection flagged the sign-in as risky. Review risk detections in Entra ID." }
    "9002325" = @{ Meaning = "Proof-up flow interrupted or failed"; Remediation = "MFA registration was not completed. User must retry MFA setup." }
}
#endregion

#region ─── Helper: Decode AADSTS Error ─────────────────────────────────────────
function Resolve-AADSTSError {
    param([string]$ErrorCode)
    $code = $ErrorCode -replace '^AADSTS', ''
    if ($AADSTSErrors.ContainsKey($code)) {
        return $AADSTSErrors[$code]
    }
    return @{ Meaning = "Unknown error code (AADSTS$code)"; Remediation = "Search https://login.microsoftonline.com/error?code=$code for details." }
}
#endregion

#region ─── Retrieve Sign-In Logs ───────────────────────────────────────────────
Write-Host "`n[*] Building query filter..." -ForegroundColor Cyan

$startDate = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filters = @("createdDateTime ge $startDate")

if ($UserPrincipalName) {
    $filters += "userPrincipalName eq '$UserPrincipalName'"
}
if ($AppId) {
    $filters += "appId eq '$AppId'"
}
if ($AppDisplayName) {
    $filters += "appDisplayName eq '$AppDisplayName'"
}

if ($filters.Count -eq 1 -and -not $UserPrincipalName -and -not $AppId -and -not $AppDisplayName) {
    Write-Error "You must specify at least one of: -UserPrincipalName, -AppId, or -AppDisplayName"
    return
}

$filterString = $filters -join ' and '
Write-Host "    Filter: $filterString" -ForegroundColor Gray

Write-Host "[*] Retrieving sign-in logs (up to $Top records)..." -ForegroundColor Cyan

$uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filterString&`$top=$Top&`$orderby=createdDateTime desc"
$allSignIns = [System.Collections.Generic.List[object]]::new()

try {
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        if ($response.value) {
            $response.value | ForEach-Object { $allSignIns.Add($_) }
        }
        # Safely check for next page link (avoids strict mode property-not-found error)
        $uri = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }
    } while ($uri -and $allSignIns.Count -lt $Top)
} catch {
    Write-Error "Failed to retrieve sign-in logs: $($_.Exception.Message)"
    return
}

if ($allSignIns.Count -eq 0) {
    Write-Warning "No sign-in logs found matching the criteria."
    return
}

Write-Host "    Retrieved $($allSignIns.Count) sign-in event(s)" -ForegroundColor Green
#endregion

#region ─── Parse and Enrich Sign-In Records ────────────────────────────────────
# Helper to safely get a property from a PSObject (avoids StrictMode errors)
function Get-SafeProperty {
    param($Object, [string]$Property)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.ContainsKey($Property)) { return $Object[$Property] }
        return $null
    }
    if ($Object.PSObject.Properties[$Property]) { return $Object.$Property }
    return $null
}

$enrichedLogs = @(foreach ($log in $allSignIns) {
    $status = Get-SafeProperty $log 'status'
    $errorCode = if ($status) { Get-SafeProperty $status 'errorCode' } else { 0 }
    $aadstsInfo = if ($errorCode -and $errorCode -ne 0) {
        Resolve-AADSTSError -ErrorCode "$errorCode"
    } else {
        @{ Meaning = "Success"; Remediation = "N/A" }
    }

    $location = Get-SafeProperty $log 'location'
    $deviceDetail = Get-SafeProperty $log 'deviceDetail'
    $geoCoords = if ($location) { Get-SafeProperty $location 'geoCoordinates' } else { $null }
    $authDetails = Get-SafeProperty $log 'authenticationDetails'

    [PSCustomObject]@{
        Timestamp        = [datetime]$log.createdDateTime
        UserPrincipalName = Get-SafeProperty $log 'userPrincipalName'
        UserId           = Get-SafeProperty $log 'userId'
        AppDisplayName   = Get-SafeProperty $log 'appDisplayName'
        AppId            = Get-SafeProperty $log 'appId'
        ResourceDisplayName = Get-SafeProperty $log 'resourceDisplayName'
        IPAddress        = Get-SafeProperty $log 'ipAddress'
        City             = if ($location) { Get-SafeProperty $location 'city' } else { $null }
        State            = if ($location) { Get-SafeProperty $location 'state' } else { $null }
        Country          = if ($location) { Get-SafeProperty $location 'countryOrRegion' } else { $null }
        Latitude         = if ($geoCoords) { Get-SafeProperty $geoCoords 'latitude' } else { $null }
        Longitude        = if ($geoCoords) { Get-SafeProperty $geoCoords 'longitude' } else { $null }
        DeviceName       = if ($deviceDetail) { Get-SafeProperty $deviceDetail 'displayName' } else { $null }
        OperatingSystem  = if ($deviceDetail) { Get-SafeProperty $deviceDetail 'operatingSystem' } else { $null }
        Browser          = if ($deviceDetail) { Get-SafeProperty $deviceDetail 'browser' } else { $null }
        IsManaged        = if ($deviceDetail) { Get-SafeProperty $deviceDetail 'isManaged' } else { $null }
        IsCompliant      = if ($deviceDetail) { Get-SafeProperty $deviceDetail 'isCompliant' } else { $null }
        TrustType        = if ($deviceDetail) { Get-SafeProperty $deviceDetail 'trustType' } else { $null }
        ClientAppUsed    = Get-SafeProperty $log 'clientAppUsed'
        ConditionalAccess = Get-SafeProperty $log 'conditionalAccessStatus'
        RiskLevel        = Get-SafeProperty $log 'riskLevelDuringSignIn'
        RiskState        = Get-SafeProperty $log 'riskState'
        MfaDetail        = Get-SafeProperty $log 'mfaDetail'
        ErrorCode        = $errorCode
        FailureReason    = if ($status) { Get-SafeProperty $status 'failureReason' } else { $null }
        ErrorMeaning     = $aadstsInfo.Meaning
        Remediation      = $aadstsInfo.Remediation
        Status           = if ($errorCode -eq 0) { "Success" } else { "Failure" }
        CorrelationId    = Get-SafeProperty $log 'correlationId'
        AuthMethod       = if ($authDetails) { ($authDetails | Select-Object -First 1).authenticationMethod } else { $null }
        MfaResult        = if ($authDetails) { ($authDetails | Where-Object { $_.authenticationMethod -ne 'Password' } | Select-Object -First 1).succeeded } else { $null }
    }
})

Write-Host "[*] Enriched $($enrichedLogs.Count) records with error decoding" -ForegroundColor Green
#endregion

#region ─── Anomaly Detection Engine ────────────────────────────────────────────
Write-Host "`n[*] Running anomaly detectors..." -ForegroundColor Cyan

$anomalies = [System.Collections.Generic.List[object]]::new()

# ── Helper: Haversine distance (km) between two lat/lon points ──
function Get-HaversineDistance {
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $R = 6371 # Earth radius in km
    $dLat = [Math]::PI * ($Lat2 - $Lat1) / 180
    $dLon = [Math]::PI * ($Lon2 - $Lon1) / 180
    $a = [Math]::Sin($dLat / 2) * [Math]::Sin($dLat / 2) +
         [Math]::Cos([Math]::PI * $Lat1 / 180) * [Math]::Cos([Math]::PI * $Lat2 / 180) *
         [Math]::Sin($dLon / 2) * [Math]::Sin($dLon / 2)
    $c = 2 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a))
    return $R * $c
}

# ── 1. Impossible Travel Detection ──
Write-Host "    [1/6] Impossible travel..." -ForegroundColor Gray
$userGroups = $enrichedLogs | Where-Object { $_.Latitude -and $_.Longitude } |
    Sort-Object Timestamp | Group-Object UserPrincipalName

foreach ($group in $userGroups) {
    $events = @($group.Group)
    for ($i = 1; $i -lt $events.Count; $i++) {
        $prev = $events[$i - 1]
        $curr = $events[$i]
        if (-not $prev.Latitude -or -not $curr.Latitude) { continue }

        $distKm = Get-HaversineDistance -Lat1 $prev.Latitude -Lon1 $prev.Longitude -Lat2 $curr.Latitude -Lon2 $curr.Longitude
        $timeDiffHours = ($curr.Timestamp - $prev.Timestamp).TotalHours

        if ($timeDiffHours -gt 0 -and $distKm -gt 100) {
            $speedKmH = $distKm / $timeDiffHours
            # Flag if speed > 900 km/h (faster than commercial flight realistic travel)
            if ($speedKmH -gt 900) {
                $detailMsg = "Traveled {0:N0} km in {1:N1} hrs ({2:N0} km/h): {3},{4} -> {5},{6}" -f $distKm, $timeDiffHours, $speedKmH, $prev.City, $prev.Country, $curr.City, $curr.Country
                $anomalies.Add([PSCustomObject]@{
                    Type        = "Impossible Travel"
                    Severity    = "High"
                    User        = $curr.UserPrincipalName
                    Timestamp   = $curr.Timestamp
                    Details     = $detailMsg
                    IPAddress   = $curr.IPAddress
                    CorrelationId = $curr.CorrelationId
                })
            }
        }
    }
}

# ── 2. Burst Login Detection (credential stuffing / brute-force) ──
Write-Host "    [2/6] Burst logins..." -ForegroundColor Gray
$burstWindow = 5 # minutes
$burstThreshold = 10 # attempts within window

foreach ($group in ($enrichedLogs | Sort-Object Timestamp | Group-Object UserPrincipalName)) {
    $events = @($group.Group)
    for ($i = 0; $i -lt $events.Count; $i++) {
        $windowEnd = $events[$i].Timestamp.AddMinutes($burstWindow)
        $windowEvents = @($events | Where-Object { $_.Timestamp -ge $events[$i].Timestamp -and $_.Timestamp -le $windowEnd })
        if ($windowEvents.Count -ge $burstThreshold) {
            $failures = @($windowEvents | Where-Object { $_.Status -eq 'Failure' })
            $anomalies.Add([PSCustomObject]@{
                Type        = "Burst Logins"
                Severity    = if ($failures.Count -ge ($burstThreshold * 0.8)) { "High" } else { "Medium" }
                User        = $group.Name
                Timestamp   = $events[$i].Timestamp
                Details     = "$($windowEvents.Count) sign-in attempts in $burstWindow min ($($failures.Count) failures). IPs: $(($windowEvents.IPAddress | Sort-Object -Unique) -join ', ')"
                IPAddress   = ($windowEvents | Select-Object -First 1).IPAddress
                CorrelationId = ($windowEvents | Select-Object -First 1).CorrelationId
            })
            # Skip ahead to avoid duplicate alerts for overlapping windows
            $i += ($windowEvents.Count - 1)
        }
    }
}

# ── 3. Geo-Anomaly Detection (new/unusual countries) ──
Write-Host "    [3/6] Geo-anomalies (new countries)..." -ForegroundColor Gray
foreach ($group in ($enrichedLogs | Where-Object { $_.Country } | Group-Object UserPrincipalName)) {
    $countries = @($group.Group | Select-Object -ExpandProperty Country -Unique)
    if ($countries.Count -gt 1) {
        # The most frequent country is considered "home"
        $homeCountry = ($group.Group | Group-Object Country | Sort-Object Count -Descending | Select-Object -First 1).Name
        $foreignEvents = @($group.Group | Where-Object { $_.Country -ne $homeCountry })
        foreach ($fe in $foreignEvents) {
            $anomalies.Add([PSCustomObject]@{
                Type        = "Geo-Anomaly"
                Severity    = "Medium"
                User        = $fe.UserPrincipalName
                Timestamp   = $fe.Timestamp
                Details     = "Sign-in from unusual country '$($fe.Country)' (home: $homeCountry). City: $($fe.City). IP: $($fe.IPAddress)"
                IPAddress   = $fe.IPAddress
                CorrelationId = $fe.CorrelationId
            })
        }
    }
}

# ── 4. Device/OS Shift Detection ──
Write-Host "    [4/6] Device/OS shifts..." -ForegroundColor Gray
foreach ($group in ($enrichedLogs | Where-Object { $_.OperatingSystem } | Group-Object UserPrincipalName)) {
    $osList = @($group.Group | Select-Object -ExpandProperty OperatingSystem -Unique | Where-Object { $_ })
    if ($osList.Count -gt 2) {
        # More than 2 different OS in the window is unusual
        $anomalies.Add([PSCustomObject]@{
            Type        = "Device/OS Shift"
            Severity    = "Low"
            User        = $group.Name
            Timestamp   = ($group.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
            Details     = "User authenticated from $($osList.Count) different OS platforms: $($osList -join ', ')"
            IPAddress   = ($group.Group | Select-Object -First 1).IPAddress
            CorrelationId = ($group.Group | Select-Object -First 1).CorrelationId
        })
    }

    $browserList = @($group.Group | Select-Object -ExpandProperty Browser -Unique | Where-Object { $_ })
    if ($browserList.Count -gt 4) {
        $anomalies.Add([PSCustomObject]@{
            Type        = "Device/Browser Shift"
            Severity    = "Low"
            User        = $group.Name
            Timestamp   = ($group.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
            Details     = "User authenticated from $($browserList.Count) different browsers: $($browserList -join ', ')"
            IPAddress   = ($group.Group | Select-Object -First 1).IPAddress
            CorrelationId = ($group.Group | Select-Object -First 1).CorrelationId
        })
    }
}

# ── 5. Unusual Hours Detection ──
Write-Host "    [5/6] Unusual hours..." -ForegroundColor Gray
$offHoursStart = 22 # 10 PM
$offHoursEnd = 5    # 5 AM

$offHoursEvents = @($enrichedLogs | Where-Object {
    $hour = $_.Timestamp.Hour
    ($hour -ge $offHoursStart) -or ($hour -lt $offHoursEnd)
})

if ($offHoursEvents.Count -gt 0) {
    $offHoursByUser = $offHoursEvents | Group-Object UserPrincipalName
    foreach ($group in $offHoursByUser) {
        if ($group.Count -ge 3) {
            $anomalies.Add([PSCustomObject]@{
                Type        = "Unusual Hours"
                Severity    = "Low"
                User        = $group.Name
                Timestamp   = ($group.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
                Details     = "$($group.Count) sign-ins during off-hours (${offHoursStart}:00-${offHoursEnd}:00 UTC). Times: $(($group.Group | Select-Object -First 5 | ForEach-Object { $_.Timestamp.ToString('HH:mm') }) -join ', ')"
                IPAddress   = ($group.Group | Select-Object -First 1).IPAddress
                CorrelationId = ($group.Group | Select-Object -First 1).CorrelationId
            })
        }
    }
}

# ── 6. MFA Failure Detection ──
Write-Host "    [6/6] MFA failures..." -ForegroundColor Gray
$mfaFailures = @($enrichedLogs | Where-Object {
    $_.ErrorCode -in @(50074, 50076, 50078, 50079, 50072, 500121, 53000) -or
    $_.MfaResult -eq $false
})

if ($mfaFailures.Count -gt 0) {
    $mfaByUser = $mfaFailures | Group-Object UserPrincipalName
    foreach ($group in $mfaByUser) {
        $severity = if ($group.Count -ge 5) { "High" } elseif ($group.Count -ge 3) { "Medium" } else { "Low" }
        $anomalies.Add([PSCustomObject]@{
            Type        = "MFA Failure"
            Severity    = $severity
            User        = $group.Name
            Timestamp   = ($group.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
            Details     = "$($group.Count) MFA-related failures. Errors: $(($group.Group.ErrorCode | Sort-Object -Unique) -join ', '). Apps: $(($group.Group.AppDisplayName | Sort-Object -Unique) -join ', ')"
            IPAddress   = ($group.Group | Select-Object -First 1).IPAddress
            CorrelationId = ($group.Group | Select-Object -First 1).CorrelationId
        })
    }
}

Write-Host "    Detected $($anomalies.Count) anomaly/anomalies" -ForegroundColor $(if ($anomalies.Count -gt 0) { 'Yellow' } else { 'Green' })
#endregion

#region ─── Generate HTML Dashboard ─────────────────────────────────────────────
Write-Host "`n[*] Generating HTML dashboard..." -ForegroundColor Cyan

# Prepare data for charts
$successCount = @($enrichedLogs | Where-Object { $_.Status -eq 'Success' }).Count
$failureCount = @($enrichedLogs | Where-Object { $_.Status -eq 'Failure' }).Count

$errorBreakdown = $enrichedLogs | Where-Object { $_.ErrorCode -ne 0 } |
    Group-Object ErrorCode | Sort-Object Count -Descending | Select-Object -First 10

$hourlyData = $enrichedLogs | Group-Object { $_.Timestamp.ToString("yyyy-MM-dd HH:00") } |
    Sort-Object Name | ForEach-Object {
        @{ Hour = $_.Name; Total = $_.Count; Failures = @($_.Group | Where-Object { $_.Status -eq 'Failure' }).Count }
    }

$countryData = $enrichedLogs | Where-Object { $_.Country } |
    Group-Object Country | Sort-Object Count -Descending | Select-Object -First 10

$appData = $enrichedLogs | Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 10

$caData = $enrichedLogs | Where-Object { $_.ConditionalAccess } |
    Group-Object ConditionalAccess | Sort-Object Count -Descending

# Build JSON data for charts
$hourlyLabelsJson = ($hourlyData | ForEach-Object { "`"$($_.Hour)`"" }) -join ','
$hourlyTotalJson = ($hourlyData | ForEach-Object { $_.Total }) -join ','
$hourlyFailJson = ($hourlyData | ForEach-Object { $_.Failures }) -join ','

$errorLabelsJson = ($errorBreakdown | ForEach-Object { "`"AADSTS$($_.Name)`"" }) -join ','
$errorCountsJson = ($errorBreakdown | ForEach-Object { $_.Count }) -join ','

$countryLabelsJson = ($countryData | ForEach-Object { "`"$($_.Name)`"" }) -join ','
$countryCountsJson = ($countryData | ForEach-Object { $_.Count }) -join ','

$appLabelsJson = ($appData | ForEach-Object { "`"$($_.Name -replace '"','\"')`"" }) -join ','
$appCountsJson = ($appData | ForEach-Object { $_.Count }) -join ','

# Build anomaly table rows
$anomalyRowsHtml = if ($anomalies.Count -gt 0) {
    ($anomalies | Sort-Object @{Expression={
        switch ($_.Severity) { "High" { 0 } "Medium" { 1 } "Low" { 2 } default { 3 } }
    }} | ForEach-Object {
        $sevClass = switch ($_.Severity) { "High" { "sev-high" } "Medium" { "sev-medium" } "Low" { "sev-low" } default { "" } }
        "<tr class=`"$sevClass`"><td>$($_.Type)</td><td>$($_.Severity)</td><td>$($_.User)</td><td>$($_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Details))</td><td>$($_.IPAddress)</td></tr>"
    }) -join "`n"
} else {
    "<tr><td colspan='6' style='text-align:center;color:#27ae60;'>No anomalies detected</td></tr>"
}

# Build sign-in log table rows (last 100 for performance)
$logRowsHtml = ($enrichedLogs | Sort-Object Timestamp -Descending | Select-Object -First 100 | ForEach-Object {
    $statusClass = if ($_.Status -eq 'Failure') { "status-fail" } else { "status-ok" }
    $errorInfo = if ($_.ErrorCode -ne 0) { "AADSTS$($_.ErrorCode): $([System.Web.HttpUtility]::HtmlEncode($_.ErrorMeaning))" } else { "" }
    "<tr class=`"$statusClass`"><td>$($_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$($_.UserPrincipalName)</td><td>$($_.AppDisplayName)</td><td>$($_.Status)</td><td>$errorInfo</td><td>$($_.IPAddress)</td><td>$($_.City), $($_.Country)</td><td>$($_.OperatingSystem)</td><td>$($_.ConditionalAccess)</td></tr>"
}) -join "`n"

# Build error detail rows
$errorDetailHtml = ($enrichedLogs | Where-Object { $_.ErrorCode -ne 0 } |
    Sort-Object Timestamp -Descending | Select-Object -First 50 | ForEach-Object {
    "<tr><td>AADSTS$($_.ErrorCode)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.ErrorMeaning))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Remediation))</td><td>$($_.UserPrincipalName)</td><td>$($_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$($_.AppDisplayName)</td></tr>"
}) -join "`n"

# Summary stats
$uniqueUsers = @($enrichedLogs | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
$uniqueApps = @($enrichedLogs | Select-Object -ExpandProperty AppDisplayName -Unique).Count
$uniqueIPs = @($enrichedLogs | Select-Object -ExpandProperty IPAddress -Unique).Count
$highAnomalies = @($anomalies | Where-Object { $_.Severity -eq 'High' }).Count
$medAnomalies = @($anomalies | Where-Object { $_.Severity -eq 'Medium' }).Count
$reportTitle = if ($UserPrincipalName) { "Sign-In Triage: $UserPrincipalName" }
               elseif ($AppDisplayName) { "Sign-In Triage: $AppDisplayName" }
               elseif ($AppId) { "Sign-In Triage: App $AppId" }
               else { "Sign-In Triage Report" }
$generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$timeRange = "$HoursBack hours (since $startDate)"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$reportTitle</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f1419; color: #e1e8ed; line-height: 1.5; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
header { background: linear-gradient(135deg, #1a1f2e 0%, #2d1b4e 100%); padding: 30px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #2d3748; }
header h1 { font-size: 1.8em; color: #fff; margin-bottom: 8px; }
header .meta { color: #a0aec0; font-size: 0.9em; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: #1a2332; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #2d3748; }
.stat-card .value { font-size: 2em; font-weight: 700; }
.stat-card .label { color: #a0aec0; font-size: 0.85em; margin-top: 4px; }
.stat-card.success .value { color: #27ae60; }
.stat-card.failure .value { color: #e74c3c; }
.stat-card.warning .value { color: #f39c12; }
.stat-card.info .value { color: #3498db; }
.section { background: #1a2332; border-radius: 10px; padding: 24px; margin-bottom: 24px; border: 1px solid #2d3748; }
.section h2 { color: #fff; margin-bottom: 16px; font-size: 1.3em; border-bottom: 2px solid #2d3748; padding-bottom: 8px; }
.charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 24px; margin-bottom: 24px; }
.chart-card { background: #1a2332; border-radius: 10px; padding: 20px; border: 1px solid #2d3748; }
.chart-card h3 { color: #a0aec0; margin-bottom: 12px; font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.5px; }
canvas { max-height: 280px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
th { background: #243447; color: #a0aec0; padding: 10px 12px; text-align: left; position: sticky; top: 0; }
td { padding: 8px 12px; border-bottom: 1px solid #2d3748; }
tr:hover { background: #243447; }
.sev-high { background: rgba(231, 76, 60, 0.15); }
.sev-high td:nth-child(2) { color: #e74c3c; font-weight: 700; }
.sev-medium { background: rgba(243, 156, 18, 0.1); }
.sev-medium td:nth-child(2) { color: #f39c12; font-weight: 700; }
.sev-low td:nth-child(2) { color: #3498db; }
.status-fail { color: #e8a0a0; }
.status-ok { color: #a0e8a0; }
.table-container { max-height: 500px; overflow-y: auto; border-radius: 8px; }
.tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.tab { padding: 8px 16px; background: #243447; border: none; color: #a0aec0; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 0.9em; }
.tab.active { background: #2d3748; color: #fff; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.filter-bar { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.filter-bar input, .filter-bar select { background: #0f1419; border: 1px solid #2d3748; color: #e1e8ed; padding: 8px 12px; border-radius: 6px; font-size: 0.85em; }
.filter-bar input { min-width: 250px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 600; }
.badge-high { background: #e74c3c; color: #fff; }
.badge-medium { background: #f39c12; color: #000; }
.badge-low { background: #3498db; color: #fff; }
footer { text-align: center; color: #4a5568; font-size: 0.8em; padding: 20px; }
@media (max-width: 768px) { .charts-grid { grid-template-columns: 1fr; } .stats-grid { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<div class="container">
<header>
    <h1>$reportTitle</h1>
    <div class="meta">Generated: $generatedAt | Time Range: $timeRange | Records: $($enrichedLogs.Count)</div>
</header>

<!-- Stats Cards -->
<div class="stats-grid">
    <div class="stat-card success"><div class="value">$successCount</div><div class="label">Successful Sign-ins</div></div>
    <div class="stat-card failure"><div class="value">$failureCount</div><div class="label">Failed Sign-ins</div></div>
    <div class="stat-card warning"><div class="value">$($anomalies.Count)</div><div class="label">Anomalies Detected</div></div>
    <div class="stat-card info"><div class="value">$uniqueUsers</div><div class="label">Unique Users</div></div>
    <div class="stat-card info"><div class="value">$uniqueApps</div><div class="label">Unique Apps</div></div>
    <div class="stat-card info"><div class="value">$uniqueIPs</div><div class="label">Unique IPs</div></div>
</div>

<!-- Charts -->
<div class="charts-grid">
    <div class="chart-card">
        <h3>Sign-in Volume Over Time</h3>
        <canvas id="timelineChart"></canvas>
    </div>
    <div class="chart-card">
        <h3>Success vs Failure</h3>
        <canvas id="pieChart"></canvas>
    </div>
    <div class="chart-card">
        <h3>Top Error Codes</h3>
        <canvas id="errorChart"></canvas>
    </div>
    <div class="chart-card">
        <h3>Sign-ins by Country</h3>
        <canvas id="countryChart"></canvas>
    </div>
    <div class="chart-card">
        <h3>Sign-ins by Application</h3>
        <canvas id="appChart"></canvas>
    </div>
    <div class="chart-card">
        <h3>Conditional Access Results</h3>
        <canvas id="caChart"></canvas>
    </div>
</div>

<!-- Anomalies Section -->
<div class="section">
    <h2>Anomaly Detection Results <span class="badge badge-high">$highAnomalies High</span> <span class="badge badge-medium">$medAnomalies Medium</span></h2>
    <div class="table-container">
        <table>
            <thead><tr><th>Type</th><th>Severity</th><th>User</th><th>Timestamp (UTC)</th><th>Details</th><th>IP Address</th></tr></thead>
            <tbody>$anomalyRowsHtml</tbody>
        </table>
    </div>
</div>

<!-- Error Details Section -->
<div class="section">
    <h2>Error Code Analysis</h2>
    <div class="table-container">
        <table>
            <thead><tr><th>Error Code</th><th>Meaning</th><th>Remediation</th><th>User</th><th>Timestamp</th><th>Application</th></tr></thead>
            <tbody>$errorDetailHtml</tbody>
        </table>
    </div>
</div>

<!-- Sign-In Logs Section -->
<div class="section">
    <h2>Sign-In Logs (Most Recent 100)</h2>
    <div class="filter-bar">
        <input type="text" id="logFilter" placeholder="Filter logs (user, app, IP, error)..." onkeyup="filterTable()">
        <select id="statusFilter" onchange="filterTable()">
            <option value="">All Statuses</option>
            <option value="Success">Success</option>
            <option value="Failure">Failure</option>
        </select>
    </div>
    <div class="table-container">
        <table id="logTable">
            <thead><tr><th>Timestamp</th><th>User</th><th>Application</th><th>Status</th><th>Error</th><th>IP Address</th><th>Location</th><th>OS</th><th>CA Status</th></tr></thead>
            <tbody>$logRowsHtml</tbody>
        </table>
    </div>
</div>

<footer>
    Entra ID Sign-In Triage Report | Generated by Invoke-EntraSignInTriage.ps1 | $generatedAt
</footer>
</div>

<script>
// Chart.js defaults
Chart.defaults.color = '#a0aec0';
Chart.defaults.borderColor = '#2d3748';

// Timeline Chart
new Chart(document.getElementById('timelineChart'), {
    type: 'bar',
    data: {
        labels: [$hourlyLabelsJson],
        datasets: [
            { label: 'Total', data: [$hourlyTotalJson], backgroundColor: 'rgba(52, 152, 219, 0.7)', borderRadius: 4 },
            { label: 'Failures', data: [$hourlyFailJson], backgroundColor: 'rgba(231, 76, 60, 0.7)', borderRadius: 4 }
        ]
    },
    options: { responsive: true, plugins: { legend: { position: 'top' } }, scales: { x: { ticks: { maxRotation: 45 } } } }
});

// Pie Chart
new Chart(document.getElementById('pieChart'), {
    type: 'doughnut',
    data: {
        labels: ['Success', 'Failure'],
        datasets: [{ data: [$successCount, $failureCount], backgroundColor: ['#27ae60', '#e74c3c'], borderWidth: 0 }]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
});

// Error Chart
new Chart(document.getElementById('errorChart'), {
    type: 'bar',
    data: {
        labels: [$errorLabelsJson],
        datasets: [{ label: 'Count', data: [$errorCountsJson], backgroundColor: 'rgba(243, 156, 18, 0.7)', borderRadius: 4 }]
    },
    options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } } }
});

// Country Chart
new Chart(document.getElementById('countryChart'), {
    type: 'bar',
    data: {
        labels: [$countryLabelsJson],
        datasets: [{ label: 'Sign-ins', data: [$countryCountsJson], backgroundColor: 'rgba(155, 89, 182, 0.7)', borderRadius: 4 }]
    },
    options: { responsive: true, plugins: { legend: { display: false } } }
});

// App Chart
new Chart(document.getElementById('appChart'), {
    type: 'bar',
    data: {
        labels: [$appLabelsJson],
        datasets: [{ label: 'Sign-ins', data: [$appCountsJson], backgroundColor: 'rgba(26, 188, 156, 0.7)', borderRadius: 4 }]
    },
    options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } } }
});

// CA Chart
const caLabels = [$(($caData | ForEach-Object { "`"$($_.Name)`"" }) -join ',')];
const caCounts = [$(($caData | ForEach-Object { $_.Count }) -join ',')];
const caColors = caLabels.map(l => l.includes('success') ? '#27ae60' : l.includes('failure') ? '#e74c3c' : '#f39c12');
new Chart(document.getElementById('caChart'), {
    type: 'doughnut',
    data: { labels: caLabels, datasets: [{ data: caCounts, backgroundColor: caColors, borderWidth: 0 }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
});

// Table filter
function filterTable() {
    const text = document.getElementById('logFilter').value.toLowerCase();
    const status = document.getElementById('statusFilter').value;
    const rows = document.querySelectorAll('#logTable tbody tr');
    rows.forEach(row => {
        const cells = row.textContent.toLowerCase();
        const statusCell = row.cells[3] ? row.cells[3].textContent : '';
        const matchText = !text || cells.includes(text);
        const matchStatus = !status || statusCell === status;
        row.style.display = (matchText && matchStatus) ? '' : 'none';
    });
}
</script>
</body>
</html>
"@

# Save HTML report
$reportFileName = "SignInTriage_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$reportPath = Join-Path $OutputPath $reportFileName
$html | Out-File -FilePath $reportPath -Encoding utf8
Write-Host "    Dashboard saved: $reportPath" -ForegroundColor Green
#endregion

#region ─── Console Triage Summary ──────────────────────────────────────────────
Write-Host "`n" -NoNewline
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║              ENTRA ID SIGN-IN TRIAGE SUMMARY                                ║" -ForegroundColor DarkCyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan

# Target info
$targetInfo = @()
if ($UserPrincipalName) { $targetInfo += "User: $UserPrincipalName" }
if ($AppId) { $targetInfo += "AppId: $AppId" }
if ($AppDisplayName) { $targetInfo += "App: $AppDisplayName" }
Write-Host "║  Target: $($targetInfo -join ' | ')".PadRight(77) "║" -ForegroundColor White
Write-Host "║  Period: Last $HoursBack hours | Records: $($enrichedLogs.Count)".PadRight(77) "║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan

# Overall health indicator
$failRate = if ($enrichedLogs.Count -gt 0) { [math]::Round(($failureCount / $enrichedLogs.Count) * 100, 1) } else { 0 }
$healthColor = if ($failRate -gt 50) { 'Red' } elseif ($failRate -gt 20) { 'Yellow' } else { 'Green' }
$healthIcon = if ($failRate -gt 50) { "[CRITICAL]" } elseif ($failRate -gt 20) { "[WARNING]" } else { "[HEALTHY]" }

Write-Host "║  " -ForegroundColor DarkCyan -NoNewline
Write-Host "$healthIcon" -ForegroundColor $healthColor -NoNewline
Write-Host " Failure Rate: $failRate% ($failureCount / $($enrichedLogs.Count))".PadRight(63) -NoNewline
Write-Host "║" -ForegroundColor DarkCyan

Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
Write-Host "║  STATISTICS                                                                  ║" -ForegroundColor DarkCyan
Write-Host "║  " -ForegroundColor DarkCyan -NoNewline
Write-Host "Successful: " -ForegroundColor Gray -NoNewline
Write-Host "$successCount" -ForegroundColor Green -NoNewline
Write-Host " | Failed: " -ForegroundColor Gray -NoNewline
Write-Host "$failureCount" -ForegroundColor Red -NoNewline
Write-Host " | Users: $uniqueUsers | Apps: $uniqueApps | IPs: $uniqueIPs" -ForegroundColor Gray -NoNewline
Write-Host "".PadRight($(77 - 60)) -NoNewline
Write-Host "║" -ForegroundColor DarkCyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan

# Anomalies section
Write-Host "║  ANOMALIES DETECTED: $($anomalies.Count)".PadRight(77) "║" -ForegroundColor DarkCyan
if ($anomalies.Count -gt 0) {
    $anomaliesSorted = $anomalies | Sort-Object @{Expression={
        switch ($_.Severity) { "High" { 0 } "Medium" { 1 } "Low" { 2 } default { 3 } }
    }}
    foreach ($a in $anomaliesSorted) {
        $sevColor = switch ($a.Severity) { "High" { "Red" } "Medium" { "Yellow" } "Low" { "Cyan" } default { "Gray" } }
        $sevIcon = switch ($a.Severity) { "High" { "[!!!]" } "Medium" { "[!!]" } "Low" { "[!]" } default { "[-]" } }
        Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
        Write-Host "$sevIcon " -ForegroundColor $sevColor -NoNewline
        $detail = "$($a.Type) | $($a.User) | $($a.Details)"
        if ($detail.Length -gt 68) { $detail = $detail.Substring(0, 65) + "..." }
        Write-Host $detail -ForegroundColor $sevColor
    }
} else {
    Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
    Write-Host "[OK] No anomalies detected" -ForegroundColor Green
}

Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan

# Top errors section
Write-Host "║  TOP ERRORS                                                                  ║" -ForegroundColor DarkCyan
$topErrors = $enrichedLogs | Where-Object { $_.ErrorCode -ne 0 } |
    Group-Object ErrorCode | Sort-Object Count -Descending | Select-Object -First 5

if ($topErrors) {
    foreach ($err in $topErrors) {
        $errInfo = Resolve-AADSTSError -ErrorCode "$($err.Name)"
        $errLine = "    AADSTS$($err.Name) ($($err.Count)x): $($errInfo.Meaning)"
        if ($errLine.Length -gt 75) { $errLine = $errLine.Substring(0, 72) + "..." }
        Write-Host "║  " -ForegroundColor DarkCyan -NoNewline
        Write-Host $errLine -ForegroundColor Yellow
    }
} else {
    Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
    Write-Host "[OK] No errors in the period" -ForegroundColor Green
}

Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan

# Remediation hints for top errors
if ($topErrors) {
    Write-Host "║  RECOMMENDED ACTIONS                                                         ║" -ForegroundColor DarkCyan
    $shown = @{}
    foreach ($err in ($topErrors | Select-Object -First 3)) {
        $errInfo = Resolve-AADSTSError -ErrorCode "$($err.Name)"
        if (-not $shown.ContainsKey($err.Name)) {
            $shown[$err.Name] = $true
            Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
            Write-Host "AADSTS$($err.Name): " -ForegroundColor White -NoNewline
            $rem = $errInfo.Remediation
            if ($rem.Length -gt 60) { $rem = $rem.Substring(0, 57) + "..." }
            Write-Host $rem -ForegroundColor Magenta
        }
    }
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
}

# Location summary
$locationSummary = $enrichedLogs | Where-Object { $_.Country } | Group-Object Country | Sort-Object Count -Descending | Select-Object -First 5
if ($locationSummary) {
    Write-Host "║  TOP LOCATIONS                                                               ║" -ForegroundColor DarkCyan
    foreach ($loc in $locationSummary) {
        Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
        Write-Host "$($loc.Name): $($loc.Count) sign-ins" -ForegroundColor Gray
    }
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
}

# Risk summary
$riskyEvents = @($enrichedLogs | Where-Object { $_.RiskLevel -and $_.RiskLevel -notin @('none','') })
if ($riskyEvents.Count -gt 0) {
    Write-Host "║  RISK DETECTIONS                                                             ║" -ForegroundColor DarkCyan
    $riskGroups = $riskyEvents | Group-Object RiskLevel | Sort-Object @{Expression={
        switch ($_.Name) { "high" { 0 } "medium" { 1 } "low" { 2 } default { 3 } }
    }}
    foreach ($rg in $riskGroups) {
        $riskColor = switch ($rg.Name) { "high" { "Red" } "medium" { "Yellow" } "low" { "Cyan" } default { "Gray" } }
        Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
        Write-Host "$($rg.Name.ToUpper()) risk: $($rg.Count) event(s)" -ForegroundColor $riskColor
    }
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
}

# Output file reference
Write-Host "║  OUTPUT                                                                      ║" -ForegroundColor DarkCyan
Write-Host "║    " -ForegroundColor DarkCyan -NoNewline
Write-Host "HTML Report: $reportPath" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

# Open report in default browser
if (Test-Path $reportPath) {
    Write-Host "[*] Opening report in default browser..." -ForegroundColor Cyan
    Start-Process $reportPath
}
#endregion
