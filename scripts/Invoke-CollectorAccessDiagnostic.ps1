<#
.SYNOPSIS
    Proves the exact PsExec collector failure reason for a single endpoint and
    tests ADMIN$ / SCM reachability under the actual O365AuditTool service
    identity (LocalSystem machine account or gMSA).

.DESCRIPTION
    Run this on the management server (e.g. NBRADC) in an ELEVATED PowerShell
    console. It answers the "all endpoints offline" investigation questions
    directly:

      * What service identity does the O365AuditTool service run as?
      * Can that identity reach the endpoint over SMB/TCP 445?
      * Can that identity open the endpoint ADMIN$ and Service Control Manager?
      * Can endpoint SYSTEM read and hash the collector share?
      * What is the EXACT PsExec exit code and error text for the real
        collector invocation?

    The decisive checks are executed through "psexec -s" so their network
    access is made as the management server computer account
    (DOMAIN\SERVERNAME$) or the configured gMSA -- exactly the identity the
    dashboard collector uses. A check that only runs as the interactive
    administrator (marked [interactive]) does NOT prove the service identity
    has the same access.

.PARAMETER Target
    A single, known powered-on workstation under the selected OU. Hostname
    only (no leading backslashes).

.PARAMETER InstallRoot
    O365AuditTool install root. Default: C:\temp\o365audit

.PARAMETER CollectorShareHost
    Host serving the collector share. Default: the local computer name.

.PARAMETER CollectorShareName
    Collector SMB share name. Default: o365audit

.EXAMPLE
    .\Invoke-CollectorAccessDiagnostic.ps1 -Target PC-TEST-01

.NOTES
    This is read-only diagnostics. It creates no persistent remote services
    beyond PsExec's own transient PSEXESVC. Sanitize hostnames, usernames,
    paths, and IP addresses before sharing output outside the customer
    environment.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Target,

    [string]$InstallRoot = 'C:\temp\o365audit',

    [string]$CollectorShareHost = $env:COMPUTERNAME,

    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$CollectorShareName = 'o365audit'
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [string]$Name,
        [ValidateSet('Pass', 'Fail', 'Warn', 'Info')]
        [string]$Status,
        [string]$Detail,
        [ValidateSet('service-identity', 'interactive')]
        [string]$Context = 'service-identity'
    )
    $results.Add([pscustomobject]@{
        Check   = $Name
        Status  = $Status
        Context = $Context
        Detail  = $Detail
    })
    $color = switch ($Status) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'Warn' { 'Yellow' }
        default { 'Gray' }
    }
    $tag = if ($Context -eq 'interactive') { '[interactive]' } else { '[service-identity]' }
    Write-Host ("  [{0,-4}] {1,-38} {2} {3}" -f $Status, $Name, $tag, $Detail) -ForegroundColor $color
}

# --- Resolve configuration ------------------------------------------------
$settingsPath = Join-Path $InstallRoot 'app\appsettings.Production.json'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    throw "appsettings.Production.json not found at '$settingsPath'. Pass -InstallRoot."
}
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$collector = $settings.Collector
$psexec = $collector.PsExecPath
$remoteScriptPath = $collector.RemoteScriptPath
$remoteScriptSha256 = ($collector.RemoteScriptSha256 | ForEach-Object { $_ }) -as [string]
$deviceTimeout = [int]($collector.DeviceTimeoutSeconds)
if ($deviceTimeout -le 0) { $deviceTimeout = 300 }

if (-not (Test-Path -LiteralPath $psexec)) {
    throw "PsExec not found at '$psexec' (from Production settings)."
}

# --- Service identity -----------------------------------------------------
Write-Host "`n=== Service identity ===" -ForegroundColor Cyan
$svc = Get-CimInstance Win32_Service -Filter "Name='O365AuditTool'" -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Add-Check -Name 'O365AuditTool service present' -Status 'Warn' -Detail 'Service not found; identity assumed LocalSystem.'
    $startName = 'LocalSystem'
} else {
    $startName = [string]$svc.StartName
    Add-Check -Name 'Service state' -Status ($(if ($svc.State -eq 'Running') { 'Pass' } else { 'Warn' })) -Detail "$($svc.State); StartName=$startName"
}

if ($startName -in @('LocalSystem', 'NT AUTHORITY\SYSTEM', '')) {
    $networkIdentity = "$env:USERDOMAIN\$env:COMPUTERNAME`$"
    Add-Check -Name 'Effective network identity' -Status 'Info' -Detail "LocalSystem -> endpoint access is made as machine account $networkIdentity"
} elseif ($startName -match '\$$') {
    $networkIdentity = $startName
    Add-Check -Name 'Effective network identity' -Status 'Info' -Detail "gMSA/machine account $networkIdentity"
} else {
    $networkIdentity = $startName
    Add-Check -Name 'Effective network identity' -Status 'Info' -Detail "Domain service account $networkIdentity"
}

# --- Helper to run a probe under the service network identity (psexec -s) --
function Invoke-AsServiceIdentity {
    param([string]$PowerShellCommand)
    $invokeArgs = @(
        "\\$env:COMPUTERNAME", '-accepteula', '-nobanner', '-h', '-s',
        'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $PowerShellCommand
    )
    $out = & $psexec @invokeArgs 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n").Trim() }
}

# --- Endpoint reachability ------------------------------------------------
Write-Host "`n=== Endpoint reachability: $Target ===" -ForegroundColor Cyan

try {
    $dns = Resolve-DnsName -Name $Target -ErrorAction Stop
    $addresses = ($dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress) -join ', '
    Add-Check -Name 'DNS resolution' -Status 'Pass' -Detail $addresses -Context 'interactive'
} catch {
    Add-Check -Name 'DNS resolution' -Status 'Fail' -Detail $_.Exception.Message -Context 'interactive'
}

try {
    $tcp = Test-NetConnection -ComputerName $Target -Port 445 -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) {
        Add-Check -Name 'TCP 445 (SMB)' -Status 'Pass' -Detail "RemoteAddress=$($tcp.RemoteAddress)" -Context 'interactive'
    } else {
        Add-Check -Name 'TCP 445 (SMB)' -Status 'Fail' -Detail 'No SMB connectivity: offline, firewall, or segmentation.' -Context 'interactive'
    }
} catch {
    Add-Check -Name 'TCP 445 (SMB)' -Status 'Fail' -Detail $_.Exception.Message -Context 'interactive'
}

# --- The decisive tests: ADMIN$ and SCM as the SERVICE identity -----------
Write-Host "`n=== ADMIN$ / SCM under service identity ===" -ForegroundColor Cyan

$adminShareProbe = Invoke-AsServiceIdentity -PowerShellCommand "if (Test-Path '\\$Target\ADMIN`$') { 'ADMIN_OK' } else { 'ADMIN_DENIED' }"
if ($adminShareProbe.Output -match 'ADMIN_OK') {
    Add-Check -Name 'ADMIN$ reachable as service identity' -Status 'Pass' -Detail "as $networkIdentity"
} else {
    Add-Check -Name 'ADMIN$ reachable as service identity' -Status 'Fail' -Detail "as $networkIdentity -> $($adminShareProbe.Output)"
}

$scmProbe = Invoke-AsServiceIdentity -PowerShellCommand "try { `$s = Get-Service -ComputerName '$Target' -Name 'RemoteRegistry' -ErrorAction Stop; 'SCM_OK' } catch { 'SCM_ERR: ' + `$_.Exception.Message }"
if ($scmProbe.Output -match 'SCM_OK') {
    Add-Check -Name 'Service Control Manager query' -Status 'Pass' -Detail "as $networkIdentity"
} else {
    Add-Check -Name 'Service Control Manager query' -Status 'Warn' -Detail "as $networkIdentity -> $($scmProbe.Output)"
}

# --- Collector share readable by endpoint SYSTEM --------------------------
Write-Host "`n=== Collector share ===" -ForegroundColor Cyan
try {
    $localShareOk = Test-Path -LiteralPath $remoteScriptPath
    if ($localShareOk) {
        $hash = (Get-FileHash -LiteralPath $remoteScriptPath -Algorithm SHA256).Hash
        $hashMatches = [string]::Equals($hash, $remoteScriptSha256, [StringComparison]::OrdinalIgnoreCase)
        Add-Check -Name 'Collector script hash matches pinned value' -Status ($(if ($hashMatches) { 'Pass' } else { 'Fail' })) -Detail "actual=$hash pinned=$remoteScriptSha256" -Context 'interactive'
    } else {
        Add-Check -Name 'Collector script present' -Status 'Fail' -Detail "Not found: $remoteScriptPath" -Context 'interactive'
    }
} catch {
    Add-Check -Name 'Collector script present' -Status 'Fail' -Detail $_.Exception.Message -Context 'interactive'
}

# --- REPRODUCE THE REAL COLLECTOR INVOCATION ------------------------------
# This mirrors PsExecCollectorRunner.RunAsync exactly: no -u/-p, so PsExec
# authenticates as the service identity. It captures the exact exit code and
# both output streams -- the ground truth for the "offline" classification.
Write-Host "`n=== Exact collector invocation (ground truth) ===" -ForegroundColor Cyan

$escapedPath = $remoteScriptPath.Replace("'", "''")
$inner = "`$p='$escapedPath';`$e='$($remoteScriptSha256.ToUpperInvariant())';" +
         "`$a=(Get-FileHash -LiteralPath `$p -Algorithm SHA256 -ErrorAction Stop).Hash;" +
         "if(-not [String]::Equals(`$a,`$e,[StringComparison]::OrdinalIgnoreCase)){throw 'Collector integrity validation failed.'};& `$p"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($inner))

$psexecArgs = @(
    "\\$Target", '-nobanner', '-accepteula', '-h', '-s',
    'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded
)

$stdoutFile = New-TemporaryFile
$stderrFile = New-TemporaryFile
try {
    $proc = Start-Process -FilePath $psexec -ArgumentList $psexecArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
    if (-not $proc.WaitForExit($deviceTimeout * 1000)) {
        try { $proc.Kill($true) } catch { }
        Add-Check -Name 'Collector PsExec invocation' -Status 'Fail' -Detail "Timed out after $deviceTimeout s (classified Timeout, not Offline)."
        $exit = $null
    } else {
        $exit = $proc.ExitCode
    }
    $stdout = (Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue)
    $stderr = (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue)

    if ($null -ne $exit) {
        Write-Host ""
        Write-Host "  PsExec exit code : $exit" -ForegroundColor $(if ($exit -eq 0) { 'Green' } else { 'Yellow' })
        Write-Host "  --- stderr ---" -ForegroundColor Gray
        Write-Host ("  " + ((($stderr).Trim() -split "`n") -join "`n  "))
        Write-Host "  --- stdout (first 800 chars) ---" -ForegroundColor Gray
        $stdoutPreview = ($stdout).Trim()
        if ($stdoutPreview.Length -gt 800) { $stdoutPreview = $stdoutPreview.Substring(0, 800) + ' ...' }
        Write-Host ("  " + (($stdoutPreview -split "`n") -join "`n  "))

        # Mirror the app's transient-network classification.
        $transient = @(53, 64, 67, 121, 1231, 1232, 1460, 1722, 1726)
        $combined = "$stderr`n$stdout"
        $denied = $combined -match '(?i)access is denied|erişim engellendi|erişim reddedildi'
        $networkMarker = $combined -match '(?i)network path was not found|network name is no longer available|network location cannot be reached|no such host is known|host is unreachable|rpc server is unavailable|timed out|could not start|couldn''t access|ağ yolu bulunamadı|rpc sunucusu kullanılamıyor|ana bilgisayar bilinmiyor'

        if ($exit -eq 0) {
            $verdict = 'SUCCESS: collector returned exit 0. Endpoint payload should persist.'
            $vcolor = 'Green'
        } elseif ($denied) {
            $verdict = "AUTHORIZATION: access denied. App classifies this as ERROR (not Offline). Service identity $networkIdentity is not an endpoint local administrator, or ADMIN`$/SCM is restricted for it."
            $vcolor = 'Red'
        } elseif (($transient -contains $exit) -or $networkMarker) {
            $verdict = "NETWORK/OFFLINE: exit $exit maps to the transient-network classifier. Endpoint is unreachable over SMB from this server (firewall/445, ADMIN`$ disabled, stale DNS, or truly offline) -- NOT plain access-denied. This is what makes a powered-on device show as Offline."
            $vcolor = 'Yellow'
        } else {
            $verdict = "UNCLASSIFIED: exit $exit with text not matched by the offline/denied markers. App classifies this as ERROR. Capture this text for a marker update."
            $vcolor = 'Magenta'
        }
        Write-Host "`n  VERDICT: $verdict" -ForegroundColor $vcolor
        Add-Check -Name 'Collector PsExec invocation' -Status ($(if ($exit -eq 0) { 'Pass' } else { 'Fail' })) -Detail "exit=$exit"
    }
} finally {
    Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
}

# --- Summary --------------------------------------------------------------
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize -Wrap

Write-Host "Interpretation (matches docs/DEPLOYMENT-DC.md troubleshooting):" -ForegroundColor Cyan
Write-Host "  * TCP 445 Fail                      -> network/DNS/firewall/offline."
Write-Host "  * TCP 445 Pass + ADMIN`$ Fail        -> service identity lacks endpoint admin rights or ADMIN`$ disabled."
Write-Host "  * ADMIN`$ Pass + collector exit != 0 -> inspect SCM, EDR (PSEXESVC), and the exact error text above."
Write-Host "  * A powered-on device showing Offline in the dashboard means the collector hit a NETWORK/OFFLINE exit code, not access-denied."
