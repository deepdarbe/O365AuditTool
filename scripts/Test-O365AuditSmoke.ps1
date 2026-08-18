[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AppDirectory,

    [ValidateRange(1024, 65535)]
    [int]$Port = 5099
)

$ErrorActionPreference = 'Stop'
$AppDirectory = [IO.Path]::GetFullPath($AppDirectory)
$application = Join-Path $AppDirectory 'O365AuditTool.exe'
if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
    throw "Self-contained application was not found: '$application'."
}

$startInfo = New-Object Diagnostics.ProcessStartInfo
$startInfo.FileName = $application
$startInfo.WorkingDirectory = $AppDirectory
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.EnvironmentVariables['ASPNETCORE_ENVIRONMENT'] = 'Development'
$startInfo.EnvironmentVariables['ASPNETCORE_URLS'] = "http://127.0.0.1:$Port"
$windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$smokeRole = @(
    $windowsIdentity.Groups |
        ForEach-Object {
            try { $_.Translate([Security.Principal.NTAccount]).Value }
            catch { $null }
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)[0]
if ([string]::IsNullOrWhiteSpace($smokeRole)) {
    throw 'Current Windows identity does not expose a group for authenticated smoke RBAC.'
}
$startInfo.EnvironmentVariables['Auth__RoleMappings__AuditReader__0'] = $smokeRole

$process = New-Object Diagnostics.Process
$process.StartInfo = $startInfo
$null = $process.Start()

function Get-HttpStatus {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$UseDefaultCredentials
    )

    try {
        $requestParameters = @{
            Uri = $Uri
            UseBasicParsing = $true
            TimeoutSec = 5
        }
        if ($UseDefaultCredentials) {
            $requestParameters.UseDefaultCredentials = $true
            if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('AllowUnencryptedAuthentication')) {
                $requestParameters.AllowUnencryptedAuthentication = $true
            }
        }
        return [int](Invoke-WebRequest @requestParameters).StatusCode
    }
    catch {
        if ($null -ne $_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        throw
    }
}

try {
    $healthStatus = 0
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        if ($process.HasExited) {
            $stderr = $process.StandardError.ReadToEnd()
            throw "Application exited during startup with code $($process.ExitCode). $stderr"
        }

        try {
            $healthStatus = Get-HttpStatus -Uri "http://127.0.0.1:$Port/health"
            if ($healthStatus -eq 200) { break }
        }
        catch {}
        Start-Sleep -Milliseconds 500
    }

    $dashboardStatus = Get-HttpStatus -Uri "http://127.0.0.1:$Port/"
    $apiStatus = Get-HttpStatus -Uri "http://127.0.0.1:$Port/api/inventory/devices"
    $authenticatedDashboardStatus = Get-HttpStatus `
        -Uri "http://127.0.0.1:$Port/" `
        -UseDefaultCredentials
    $authenticatedApiStatus = Get-HttpStatus `
        -Uri "http://127.0.0.1:$Port/api/inventory/devices" `
        -UseDefaultCredentials
    if (
        $healthStatus -ne 200 -or
        $dashboardStatus -ne 401 -or
        $apiStatus -ne 401 -or
        $authenticatedDashboardStatus -ne 200 -or
        $authenticatedApiStatus -ne 200
    ) {
        throw "Smoke status mismatch. health=$healthStatus dashboardAnonymous=$dashboardStatus apiAnonymous=$apiStatus dashboardAuthenticated=$authenticatedDashboardStatus apiAuthenticated=$authenticatedApiStatus"
    }

    [pscustomobject]@{
        HealthStatus = $healthStatus
        DashboardAnonymousStatus = $dashboardStatus
        ApiAnonymousStatus = $apiStatus
        DashboardAuthenticatedStatus = $authenticatedDashboardStatus
        ApiAuthenticatedStatus = $authenticatedApiStatus
        AuthenticatedRole = $smokeRole
        ProcessId = $process.Id
    }
}
finally {
    if (-not $process.HasExited) {
        $process.Kill()
        $process.WaitForExit(5000) | Out-Null
    }
    $process.Dispose()
}
