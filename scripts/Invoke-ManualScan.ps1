[CmdletBinding()]
param(
    [string]$BaseUrl = "https://$env:COMPUTERNAME`:5080",
    [string]$OuFilter = "",
    [string]$SiteFilter = ""
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OuFilter) -and [string]::IsNullOrWhiteSpace($SiteFilter)) {
    throw 'Domain-geneli tarama kapali. -OuFilter veya -SiteFilter belirtin.'
}

$tokenResponse = Invoke-RestMethod `
    -Uri "$BaseUrl/api/security/antiforgery" `
    -Method Get `
    -UseDefaultCredentials `
    -SessionVariable auditSession
if ([string]::IsNullOrWhiteSpace([string]$tokenResponse.token)) {
    throw 'Antiforgery token alinamadi.'
}

$uri = "$BaseUrl/api/jobs/scan"
$body = @{ ouFilter = $OuFilter; siteFilter = $SiteFilter; manual = $true } | ConvertTo-Json

$response = Invoke-RestMethod `
    -Uri $uri `
    -Method Post `
    -UseDefaultCredentials `
    -WebSession $auditSession `
    -Headers @{ 'X-O365Audit-CSRF' = [string]$tokenResponse.token } `
    -ContentType 'application/json' `
    -Body $body
$response | ConvertTo-Json -Depth 4
