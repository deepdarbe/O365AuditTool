[CmdletBinding()]
param(
    [string]$BaseUrl = "http://localhost:5080",
    [string]$OuFilter = "",
    [string]$SiteFilter = ""
)

$ErrorActionPreference = 'Stop'
$uri = "$BaseUrl/api/jobs/scan"
$body = @{ ouFilter = $OuFilter; siteFilter = $SiteFilter; manual = $true } | ConvertTo-Json

$response = Invoke-RestMethod -Uri $uri -Method Post -UseDefaultCredentials -ContentType 'application/json' -Body $body
$response | ConvertTo-Json -Depth 4
