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

$process = New-Object Diagnostics.Process
$process.StartInfo = $startInfo
$null = $process.Start()

function Get-HttpStatus {
    param([Parameter(Mandatory)][string]$Uri)

    try {
        return [int](Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 5).StatusCode
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
    if ($healthStatus -ne 200 -or $dashboardStatus -ne 401 -or $apiStatus -ne 401) {
        throw "Smoke status mismatch. health=$healthStatus dashboard=$dashboardStatus api=$apiStatus"
    }

    [pscustomobject]@{
        HealthStatus = $healthStatus
        DashboardAnonymousStatus = $dashboardStatus
        ApiAnonymousStatus = $apiStatus
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
