<#
.SYNOPSIS
    Determines whether allocating a console in the CALLING process lets PsExec
    run from a session-0 service context while its output is still captured.

.DESCRIPTION
    From a Windows service (session 0) PsExec fails with
    "Couldn't access <host>: The handle is invalid." (exit 6). Measurements so
    far:

        .NET pipes, CreateNoWindow=false        -> exit 6
        batch wrapper, no "start"               -> exit 6
        batch wrapper + start /wait             -> hangs in session 0

    A child process inherits the parent's console unless CREATE_NO_WINDOW /
    DETACHED_PROCESS / CREATE_NEW_CONSOLE is used. So if the service process
    itself owns a console (AllocConsole), PsExec inherits it while the redirected
    standard streams still capture output.

    This probe runs the identical invocation twice as SYSTEM: once with no
    console (FreeConsole) and once after AllocConsole, so the console is the only
    variable.

    Run ON the management server, as SYSTEM:

        psexec.exe -accepteula -nobanner -s powershell -NoProfile `
            -ExecutionPolicy Bypass -File C:\temp\psxmodes.ps1 -Target CORELAPP

.PARAMETER Target
    A known powered-on endpoint.

.PARAMETER InstallRoot
    O365AuditTool install root. Default: C:\temp\o365audit

.NOTES
    Read-only diagnostics. Sanitize hostnames and paths before sharing output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Target,

    [string]$InstallRoot = 'C:\temp\o365audit'
)

# Native commands write status text to stderr; 'Stop' would abort the probe.
$ErrorActionPreference = 'Continue'

$settingsPath = Join-Path $InstallRoot 'app\appsettings.Production.json'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    throw "appsettings.Production.json bulunamadi: '$settingsPath'."
}
$collector = (Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).Collector
$psexec = [string]$collector.PsExecPath
$remoteScriptPath = [string]$collector.RemoteScriptPath
$remoteScriptSha256 = ([string]$collector.RemoteScriptSha256).ToUpperInvariant()
if (-not (Test-Path -LiteralPath $psexec)) {
    throw "PsExec bulunamadi: '$psexec'."
}

Add-Type -Name ConsoleApi -Namespace Probe -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool AllocConsole();
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FreeConsole();
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();
'@

Write-Host "whoami : $(whoami)"
Write-Host "psexec : $psexec ($((Get-Item $psexec).VersionInfo.FileVersion))"
Write-Host "target : $Target"
Write-Host "baslangic konsol handle: $([Probe.ConsoleApi]::GetConsoleWindow())"
Write-Host ""

$escapedPath = $remoteScriptPath.Replace("'", "''")
$inner = "`$p='$escapedPath';`$e='$remoteScriptSha256';" +
         "`$a=(Get-FileHash -LiteralPath `$p -Algorithm SHA256 -ErrorAction Stop).Hash;" +
         "if(-not [String]::Equals(`$a,`$e,[StringComparison]::OrdinalIgnoreCase)){throw 'Collector integrity validation failed.'};& `$p"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$collectorArgs = "\\$Target -nobanner -accepteula -h -s powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
$echoArgs = "\\$Target -nobanner -accepteula -h -s cmd /c echo COLLECTOR_PROBE_OK"

function Invoke-PipesRun {
    param([string]$Name, [string]$Description, [string]$PsExecArguments)
    # Exactly how PsExecCollectorRunner starts PsExec today.
    $code = 'HATA'
    $so = ''
    $se = ''
    $note = ''
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $psexec
        $psi.Arguments = $PsExecArguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow = $false
        $p = [Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        if ($p.WaitForExit(180000)) {
            $code = $p.ExitCode
        }
        else {
            $note = 'ZAMAN ASIMI (180s)'
            try { $p.Kill() } catch { }
        }
        $so = [string]$o.Result
        $se = [string]$e.Result
        $p.Dispose()
    }
    catch {
        $note = $_.Exception.Message
    }

    $captured = $so.Contains('COLLECTOR_PROBE_OK') -or $so.Contains('"schemaVersion"')
    $handleInvalid = ($so + "`n" + $se) -match '(?i)handle is invalid'
    $color = if ($code -eq 0 -and $captured) { 'Green' } elseif ($code -eq 0) { 'Yellow' } else { 'Red' }

    Write-Host ("{0,-16} {1,-26} exit={2,-6} cikti={3,-6} handleInvalid={4,-6} {5}" -f `
        $Name, $Description, $code, $captured, $handleInvalid, $note) -ForegroundColor $color

    if (-not [string]::IsNullOrWhiteSpace($se)) {
        $preview = $se.Trim()
        if ($preview.Length -gt 160) { $preview = $preview.Substring(0, 160) + ' ...' }
        Write-Host ("                 stderr: " + ($preview -replace "`r?`n", ' | ')) -ForegroundColor DarkGray
    }
    if ($captured -and $so.Contains('"schemaVersion"')) {
        Write-Host ("                 payload ilk 120: " + $so.Trim().Substring(0, [Math]::Min(120, $so.Trim().Length))) -ForegroundColor DarkGray
    }
}

# --- A: no console (what the service has today) ---------------------------
$null = [Probe.ConsoleApi]::FreeConsole()
Write-Host "--- A: KONSOLSUZ (servisin bugunku durumu) ---" -ForegroundColor Cyan
Write-Host "konsol handle: $([Probe.ConsoleApi]::GetConsoleWindow())"
Invoke-PipesRun -Name 'A1-echo'      -Description 'konsolsuz, echo'      -PsExecArguments $echoArgs
Invoke-PipesRun -Name 'A2-collector' -Description 'konsolsuz, collector' -PsExecArguments $collectorArgs

# --- B: with an allocated console (the candidate fix) ---------------------
Write-Host ""
$allocated = [Probe.ConsoleApi]::AllocConsole()
Write-Host "--- B: AllocConsole (aday duzeltme) ---" -ForegroundColor Cyan
Write-Host "AllocConsole sonucu: $allocated · konsol handle: $([Probe.ConsoleApi]::GetConsoleWindow())"
Invoke-PipesRun -Name 'B1-echo'      -Description 'konsollu, echo'       -PsExecArguments $echoArgs
Invoke-PipesRun -Name 'B2-collector' -Description 'konsollu, collector'  -PsExecArguments $collectorArgs

Write-Host ""
Write-Host "Aranan: B satirlarinda exit=0 ve cikti=True (A satirlari exit=6 kalirken)." -ForegroundColor Cyan
