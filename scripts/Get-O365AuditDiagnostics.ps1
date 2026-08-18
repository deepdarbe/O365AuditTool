[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\temp\o365audit',
    [string]$TraceIdentifier = '',
    [ValidateRange(1, 500)]
    [int]$Tail = 100
)

$ErrorActionPreference = 'Stop'
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$settingsPath = Join-Path $InstallRoot 'app\appsettings.Production.json'
if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "Production settings not found: '$settingsPath'."
}

$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$healthPort = if ($settings.Server.HealthPort) { [int]$settings.Server.HealthPort } else { 5081 }
$databasePath = ([string]$settings.ConnectionStrings.AuditDb) -replace '^\s*Data Source\s*=\s*', ''
$logDirectory = if ($settings.Diagnostics.LogDirectory) {
    [string]$settings.Diagnostics.LogDirectory
}
else {
    Join-Path $InstallRoot 'logs'
}

$service = Get-Service -Name 'O365AuditTool' -ErrorAction SilentlyContinue
$healthStatus = 'Unavailable'
$healthError = $null
try {
    $health = Invoke-RestMethod -Uri "http://localhost:$healthPort/health" -TimeoutSec 10
    $healthStatus = [string]$health.status
}
catch {
    $healthError = $_.Exception.Message
}

[pscustomobject]@{
    InstallRoot = $InstallRoot
    ServiceStatus = if ($service) { [string]$service.Status } else { 'NotInstalled' }
    HealthStatus = $healthStatus
    HealthError = $healthError
    DatabasePath = $databasePath
    DatabaseExists = Test-Path -LiteralPath $databasePath -PathType Leaf
    DatabaseBytes = if (Test-Path -LiteralPath $databasePath -PathType Leaf) {
        (Get-Item -LiteralPath $databasePath).Length
    }
    else {
        0
    }
    LogDirectory = $logDirectory
}

$logFiles = @(
    Get-ChildItem -LiteralPath $logDirectory -Filter 'server-errors-*.jsonl' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending
)
$records = foreach ($logFile in $logFiles | Select-Object -First 5) {
    foreach ($line in Get-Content -LiteralPath $logFile.FullName -Tail $Tail) {
        try {
            $line | ConvertFrom-Json
        }
        catch {
            continue
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($TraceIdentifier)) {
    $records = @($records | Where-Object traceIdentifier -EQ $TraceIdentifier)
}

$records |
    Sort-Object timestampUtc -Descending |
    Select-Object -First $Tail timestampUtc, traceIdentifier, requestMethod, requestPath, exceptionType, exceptionChain
