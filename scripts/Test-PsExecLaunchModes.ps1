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

    [string]$InstallRoot = 'C:\temp\o365audit',

    [string]$ReportPath = 'C:\temp\psxreport.txt'
)

# Native commands write status text to stderr; 'Stop' would abort the probe.
$ErrorActionPreference = 'Continue'

# FreeConsole detaches this process from its console, after which Write-Host throws
# ("getting console output buffer information"). Every result therefore goes to a
# file, which is also the evidence the operator sends back.
if (Test-Path -LiteralPath $ReportPath) { Remove-Item -LiteralPath $ReportPath -Force }
function Write-Report {
    param([string]$Text)
    [IO.File]::AppendAllText($ReportPath, $Text + [Environment]::NewLine)
}

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

Write-Report "whoami : $(whoami)"
Write-Report "psexec : $psexec ($((Get-Item $psexec).VersionInfo.FileVersion))"
Write-Report "target : $Target"
Write-Report "baslangic konsol handle: $([Probe.ConsoleApi]::GetConsoleWindow())"
Write-Report ""

$escapedPath = $remoteScriptPath.Replace("'", "''")
$inner = "`$p='$escapedPath';`$e='$remoteScriptSha256';" +
         "`$a=(Get-FileHash -LiteralPath `$p -Algorithm SHA256 -ErrorAction Stop).Hash;" +
         "if(-not [String]::Equals(`$a,`$e,[StringComparison]::OrdinalIgnoreCase)){throw 'Collector integrity validation failed.'};& `$p"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$collectorArgs = "\\$Target -nobanner -accepteula -h -s powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
$echoArgs = "\\$Target -nobanner -accepteula -h -s cmd /c echo COLLECTOR_PROBE_OK"

function Invoke-Run {
    param(
        [string]$Name,
        [string]$Description,
        [string]$PsExecArguments,
        [bool]$RedirectOut,
        [bool]$RedirectErr,
        [bool]$RedirectIn
    )
    # Output is captured only when the corresponding stream is redirected; the point of
    # the matrix is which redirection, if any, triggers exit 6 under session 0.
    $code = 'HATA'
    $so = ''
    $se = ''
    $note = ''
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $psexec
        $psi.Arguments = $PsExecArguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $RedirectOut
        $psi.RedirectStandardError = $RedirectErr
        $psi.RedirectStandardInput = $RedirectIn
        $psi.CreateNoWindow = $false
        $p = [Diagnostics.Process]::Start($psi)
        if ($RedirectIn) { $p.StandardInput.Close() }
        $o = $null
        $e = $null
        if ($RedirectOut) { $o = $p.StandardOutput.ReadToEndAsync() }
        if ($RedirectErr) { $e = $p.StandardError.ReadToEndAsync() }
        if ($p.WaitForExit(180000)) { $code = $p.ExitCode }
        else {
            $note = 'ZAMAN ASIMI (180s)'
            try { $p.Kill() } catch { }
        }
        if ($null -ne $o) { $so = [string]$o.Result }
        if ($null -ne $e) { $se = [string]$e.Result }
        $p.Dispose()
    }
    catch {
        $note = $_.Exception.Message
    }

    $captured = $so.Contains('COLLECTOR_PROBE_OK') -or $so.Contains('"schemaVersion"')
    $handleInvalid = ($so + "`n" + $se) -match '(?i)handle is invalid'
    Write-Report ("{0,-14} {1,-30} exit={2,-6} cikti={3,-6} handleInvalid={4,-6} {5}" -f `
        $Name, $Description, $code, $captured, $handleInvalid, $note)
}

# A console is allocated first: the previous run proved it is not sufficient on its
# own, so it is held constant while only the redirection varies.
$null = [Probe.ConsoleApi]::FreeConsole()
$allocated = [Probe.ConsoleApi]::AllocConsole()
Write-Report "AllocConsole: $allocated - konsol handle: $([Probe.ConsoleApi]::GetConsoleWindow())"
Write-Report ""
Write-Report "--- Yonlendirme matrisi (echo komutu, konsol sabit) ---"

Invoke-Run -Name 'M0-hicbiri'  -Description 'yonlendirme YOK'        -PsExecArguments $echoArgs -RedirectOut $false -RedirectErr $false -RedirectIn $false
Invoke-Run -Name 'M1-sadeceIn' -Description 'sadece stdin'           -PsExecArguments $echoArgs -RedirectOut $false -RedirectErr $false -RedirectIn $true
Invoke-Run -Name 'M2-sadeceOut'-Description 'sadece stdout'          -PsExecArguments $echoArgs -RedirectOut $true  -RedirectErr $false -RedirectIn $false
Invoke-Run -Name 'M3-sadeceErr'-Description 'sadece stderr'          -PsExecArguments $echoArgs -RedirectOut $false -RedirectErr $true  -RedirectIn $false
Invoke-Run -Name 'M4-hepsi'    -Description 'hepsi (mevcut kod)'     -PsExecArguments $echoArgs -RedirectOut $true  -RedirectErr $true  -RedirectIn $true

Write-Report ""
Write-Report "--- Gercek collector, yonlendirmesiz ---"
Invoke-Run -Name 'C0-hicbiri'  -Description 'collector, yonlendirme YOK' -PsExecArguments $collectorArgs -RedirectOut $false -RedirectErr $false -RedirectIn $false

Write-Report ""
Write-Report "Aranan: hangi yonlendirme exit 6'yi tetikliyor. M0/C0 = 0 ise cikti"
Write-Report "yakalamayi uzak tarafa (ADMIN$ uzerinden dosya) tasimak gerekir."
