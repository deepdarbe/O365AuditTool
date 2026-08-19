<#
.SYNOPSIS
    Reads every local diagnostic channel of an O365AuditTool installation, including the ones
    that are the only evidence left when the service does not start at all.

.DESCRIPTION
    Sections are independent: a section that cannot be read reports why and the script continues.

      * Installation state, service status, health endpoint, SQLite database
      * Failed deployment directories (.failed-*) when 'app' is missing, plus the exact
        console command that reproduces the startup failure in the foreground
      * startup-failure-*.log written by the application before it rethrows a startup exception
      * service-*.log (Warning and above from the hosted services)
      * Windows Event Log tail: Application ('.NET Runtime', 'Application Error',
        'O365AuditTool') and System Service Control Manager events 7000/7009/7031/7034
      * The configured TLS certificate: subject, issuer, validity, private key, chain status
      * server-errors-*.jsonl request exceptions, optionally filtered by trace identifier

.PARAMETER InstallRoot
    O365AuditTool install root. Default: C:\temp\o365audit

.PARAMETER TraceIdentifier
    Restricts the request exception records to one dashboard trace code.

.PARAMETER Tail
    Maximum records per log section. Default: 100

.PARAMETER EventLogDays
    Age limit for the Windows Event Log sections, in days. Default: 3

.EXAMPLE
    & C:\temp\o365audit\Get-O365AuditDiagnostics.ps1 | Format-List

.EXAMPLE
    & C:\temp\o365audit\Get-O365AuditDiagnostics.ps1 -TraceIdentifier '0HNNTC9S007EL:00000003'

.NOTES
    Read-only. Sanitize hostnames, usernames, paths and thumbprints before sharing the output
    outside the customer environment.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\temp\o365audit',
    [string]$TraceIdentifier = '',
    [ValidateRange(1, 500)]
    [int]$Tail = 100,
    [ValidateRange(1, 90)]
    [int]$EventLogDays = 3
)

$ErrorActionPreference = 'Stop'
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Write-SectionUnavailable {
    param([string]$Title, [string]$Reason)
    Write-Host "   [unavailable] $Title : $Reason" -ForegroundColor DarkYellow
}

# A failed first deployment moves the live app directory to '.failed-<id>' and has no rollback to
# restore, so 'app' does not exist in exactly the state where this script is needed most.
$failedDeployments = @()
try {
    $failedDeployments = @(
        Get-ChildItem -LiteralPath $InstallRoot -Directory -Filter '.failed-*' -Force -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending
    )
}
catch {
    Write-SectionUnavailable -Title 'failed deployment discovery' -Reason $_.Exception.Message
}

$appDirectory = Join-Path $InstallRoot 'app'
$settingsPath = Join-Path $appDirectory 'appsettings.Production.json'
$settingsSource = 'app'
if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    $settingsSource = 'missing'
    foreach ($failedDeployment in $failedDeployments) {
        $candidate = Join-Path $failedDeployment.FullName 'appsettings.Production.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $appDirectory = $failedDeployment.FullName
            $settingsPath = $candidate
            $settingsSource = $failedDeployment.Name
            break
        }
    }
}

$settings = $null
if ($settingsSource -ne 'missing') {
    try {
        $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-SectionUnavailable -Title 'production settings' -Reason $_.Exception.Message
    }
}
else {
    Write-SectionUnavailable -Title 'production settings' -Reason "No appsettings.Production.json under '$InstallRoot' (neither 'app' nor a '.failed-*' directory)."
}

$healthPort = if ($settings -and $settings.Server.HealthPort) { [int]$settings.Server.HealthPort } else { 5081 }
$certificateThumbprint = if ($settings) { [string]$settings.Server.TlsCertificateThumbprint } else { '' }
$databasePath = if ($settings) {
    ([string]$settings.ConnectionStrings.AuditDb) -replace '^\s*Data Source\s*=\s*', '' -replace ';.*$', ''
}
else {
    ''
}
if ($databasePath -and -not [IO.Path]::IsPathRooted($databasePath)) {
    $databasePath = [IO.Path]::GetFullPath((Join-Path $appDirectory ($databasePath -replace '^\.[\\/]', '')))
}
$logDirectory = if ($settings -and $settings.Diagnostics.LogDirectory) {
    [string]$settings.Diagnostics.LogDirectory
}
else {
    Join-Path $InstallRoot 'logs'
}

$service = Get-Service -Name 'O365AuditTool' -ErrorAction SilentlyContinue
$serviceBinaryPath = $null
$serviceStartName = $null
try {
    $serviceConfiguration = Get-CimInstance -ClassName Win32_Service -Filter "Name='O365AuditTool'" -ErrorAction SilentlyContinue
    if ($serviceConfiguration) {
        $serviceBinaryPath = [string]$serviceConfiguration.PathName
        $serviceStartName = [string]$serviceConfiguration.StartName
    }
}
catch {
    Write-SectionUnavailable -Title 'service configuration' -Reason $_.Exception.Message
}

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
    AppDirectory = $appDirectory
    SettingsSource = $settingsSource
    ServiceStatus = if ($service) { [string]$service.Status } else { 'NotInstalled' }
    ServiceBinaryPath = $serviceBinaryPath
    ServiceStartName = $serviceStartName
    HealthStatus = $healthStatus
    HealthError = $healthError
    DatabasePath = $databasePath
    DatabaseExists = ($databasePath -and (Test-Path -LiteralPath $databasePath -PathType Leaf))
    DatabaseBytes = if ($databasePath -and (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
        (Get-Item -LiteralPath $databasePath).Length
    }
    else {
        0
    }
    LogDirectory = $logDirectory
    FailedDeploymentCount = $failedDeployments.Count
}

Write-Section 'Failed deployments'
if ($failedDeployments.Count -eq 0) {
    Write-Host '   none'
}
else {
    foreach ($failedDeployment in $failedDeployments) {
        $executable = Join-Path $failedDeployment.FullName 'O365AuditTool.exe'
        Write-Host "   $($failedDeployment.Name)  (last write $($failedDeployment.LastWriteTime))"
        Write-Host "     settings : $(Test-Path -LiteralPath (Join-Path $failedDeployment.FullName 'appsettings.Production.json') -PathType Leaf)"
        Write-Host "     exe      : $(Test-Path -LiteralPath $executable -PathType Leaf)"
    }

    # The rollback removes 'app', so the documented "run it from the console" step has to point at
    # the failed directory instead of a path that no longer exists.
    $newestFailed = $failedDeployments[0]
    $newestExecutable = Join-Path $newestFailed.FullName 'O365AuditTool.exe'
    if (Test-Path -LiteralPath $newestExecutable -PathType Leaf) {
        Write-Host '   Reproduce the startup failure in the foreground:' -ForegroundColor Yellow
        Write-Host "     & '$newestExecutable' --environment Production" -ForegroundColor Yellow
    }
}

Write-Section "Startup failures ($logDirectory)"
try {
    $startupFailureFiles = @(
        Get-ChildItem -LiteralPath $logDirectory -Filter 'startup-failure-*.log' -File -ErrorAction Stop |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 3
    )
    if ($startupFailureFiles.Count -eq 0) {
        Write-Host '   none'
    }
    foreach ($startupFailureFile in $startupFailureFiles) {
        Write-Host "   --- $($startupFailureFile.Name) ---" -ForegroundColor Yellow
        Get-Content -LiteralPath $startupFailureFile.FullName -Tail $Tail | ForEach-Object { Write-Host "   $_" }
    }
}
catch {
    Write-SectionUnavailable -Title 'startup failure logs' -Reason $_.Exception.Message
}

Write-Section "Service log (Warning and above, last $Tail lines)"
try {
    $serviceLogFile = Get-ChildItem -LiteralPath $logDirectory -Filter 'service-*.log' -File -ErrorAction Stop |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $serviceLogFile) {
        Write-Host '   none'
    }
    else {
        Write-Host "   --- $($serviceLogFile.Name) ---" -ForegroundColor Yellow
        Get-Content -LiteralPath $serviceLogFile.FullName -Tail $Tail | ForEach-Object { Write-Host "   $_" }
    }
}
catch {
    Write-SectionUnavailable -Title 'service log' -Reason $_.Exception.Message
}

$eventLogSince = (Get-Date).AddDays(-$EventLogDays)

Write-Section "Application event log (last $EventLogDays day(s))"
$applicationEvents = foreach ($providerName in @('.NET Runtime', 'Application Error', 'O365AuditTool')) {
    try {
        # Each provider is queried on its own: an installation where the 'O365AuditTool' event
        # source was never registered must not suppress the '.NET Runtime' records that hold the
        # actual startup exception.
        Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = $providerName
            StartTime = $eventLogSince
        } -MaxEvents $Tail -ErrorAction Stop
    }
    catch {
        Write-SectionUnavailable -Title "Application/$providerName" -Reason $_.Exception.Message
    }
}
$applicationEvents = @($applicationEvents | Sort-Object TimeCreated -Descending | Select-Object -First $Tail)
if ($applicationEvents.Count -eq 0) {
    Write-Host '   none'
}
foreach ($applicationEvent in $applicationEvents) {
    Write-Host "   $($applicationEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) [$($applicationEvent.LevelDisplayName)] $($applicationEvent.ProviderName) ($($applicationEvent.Id))"
    $eventMessage = ([string]$applicationEvent.Message) -split "`r?`n" | Select-Object -First 12
    $eventMessage | ForEach-Object { Write-Host "     $_" }
}

Write-Section "Service Control Manager event log (last $EventLogDays day(s))"
try {
    $scmEvents = @(
        Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Service Control Manager'
            Id = @(7000, 7009, 7031, 7034)
            StartTime = $eventLogSince
        } -MaxEvents $Tail -ErrorAction Stop
    )
    if ($scmEvents.Count -eq 0) {
        Write-Host '   none'
    }
    foreach ($scmEvent in $scmEvents) {
        Write-Host "   $($scmEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) [$($scmEvent.Id)] $((([string]$scmEvent.Message) -split "`r?`n")[0])"
    }
}
catch {
    Write-SectionUnavailable -Title 'System/Service Control Manager' -Reason $_.Exception.Message
}

Write-Section 'TLS certificate'
if ([string]::IsNullOrWhiteSpace($certificateThumbprint)) {
    Write-Host '   Server:TlsCertificateThumbprint is not configured.'
}
else {
    $normalizedThumbprint = ($certificateThumbprint -replace '\s', '').ToUpperInvariant()
    $certificateStore = $null
    try {
        $certificateStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
        $certificateStore.Open('ReadOnly')
        # validOnly:$false on purpose: the service accepts a self-signed certificate, so the store
        # filter that hides untrusted chains would hide the certificate this script must report on.
        $certificates = @($certificateStore.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $normalizedThumbprint,
            $false))

        if ($certificates.Count -eq 0) {
            Write-Host "   Thumbprint '$normalizedThumbprint' is NOT present in LocalMachine\My." -ForegroundColor Red
        }
        foreach ($certificate in $certificates) {
            $chain = $null
            $chainValid = $null
            $chainStatus = 'not evaluated'
            try {
                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.ChainPolicy.RevocationMode = 'NoCheck'
                $chainValid = $chain.Build($certificate)
                $chainStatus = if ($chain.ChainStatus.Count -eq 0) {
                    'Ok'
                }
                else {
                    (($chain.ChainStatus | ForEach-Object { $_.Status }) -join ', ')
                }
            }
            catch {
                $chainStatus = $_.Exception.Message
            }
            finally {
                if ($chain) { $chain.Dispose() }
            }

            $enhancedKeyUsages = @(
                $certificate.Extensions |
                    Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
                    ForEach-Object { $_.EnhancedKeyUsages | ForEach-Object { $_.Value } }
            )

            # BURCUDC was imported into LocalMachine\CA instead of LocalMachine\Root, which is why
            # its chain terminates in an untrusted root.
            $issuerInRoot = $null
            $issuerInIntermediate = $null
            try {
                $issuerInRoot = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop |
                    Where-Object { $_.Subject -eq $certificate.Issuer }).Count
                $issuerInIntermediate = @(Get-ChildItem -Path 'Cert:\LocalMachine\CA' -ErrorAction Stop |
                    Where-Object { $_.Subject -eq $certificate.Issuer }).Count
            }
            catch {
                Write-SectionUnavailable -Title 'issuer store lookup' -Reason $_.Exception.Message
            }

            [pscustomobject]@{
                Thumbprint = $certificate.Thumbprint
                Subject = $certificate.Subject
                Issuer = $certificate.Issuer
                SelfSigned = ($certificate.Subject -eq $certificate.Issuer)
                NotBefore = $certificate.NotBefore
                NotAfter = $certificate.NotAfter
                CurrentlyInValidityWindow = ((Get-Date) -ge $certificate.NotBefore -and (Get-Date) -le $certificate.NotAfter)
                HasPrivateKey = $certificate.HasPrivateKey
                EnhancedKeyUsages = if ($enhancedKeyUsages.Count -eq 0) { '(none - any purpose)' } else { $enhancedKeyUsages -join ', ' }
                ChainValid = $chainValid
                ChainStatus = $chainStatus
                IssuerInLocalMachineRoot = $issuerInRoot
                IssuerInLocalMachineCA = $issuerInIntermediate
            }
        }
    }
    catch {
        Write-SectionUnavailable -Title 'TLS certificate' -Reason $_.Exception.Message
    }
    finally {
        if ($certificateStore) { $certificateStore.Close() }
    }
}

Write-Section "Request exceptions (server-errors-*.jsonl, last $Tail)"
$records = @()
try {
    $logFiles = @(
        Get-ChildItem -LiteralPath $logDirectory -Filter 'server-errors-*.jsonl' -File -ErrorAction Stop |
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
}
catch {
    Write-SectionUnavailable -Title 'request exception log' -Reason $_.Exception.Message
}

if (-not [string]::IsNullOrWhiteSpace($TraceIdentifier)) {
    $records = @($records | Where-Object traceIdentifier -EQ $TraceIdentifier)
}

$records |
    Sort-Object timestampUtc -Descending |
    Select-Object -First $Tail timestampUtc, traceIdentifier, requestMethod, requestPath, exceptionType, exceptionChain
