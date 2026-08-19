<#
.SYNOPSIS
    Measures which PsExec launch mode works from a session-0 service context and
    still lets the caller capture stdout/stderr and the exit code.

.DESCRIPTION
    The collector launches PsExec from a Windows service (session 0). There
    PsExec fails with "Couldn't access <host>: The handle is invalid." (exit 6)
    unless it gets a real console. Redirecting the standard streams to pipes
    suppresses console allocation, so the fix must both give PsExec a console
    AND still capture its output.

    Run this ON the management server, as SYSTEM:

        psexec.exe -accepteula -nobanner -s powershell -NoProfile `
            -ExecutionPolicy Bypass -File C:\temp\psxmodes.ps1 -Target CORELAPP

    Each mode runs independently; a failure in one does not stop the others.
    The mode that reports exit=0 AND output=True is the one to implement.

.PARAMETER Target
    A known powered-on endpoint.

.PARAMETER InstallRoot
    O365AuditTool install root. Default: C:\temp\o365audit

.NOTES
    Read-only diagnostics. Temporary files are removed. Sanitize hostnames and
    paths before sharing the output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Target,

    [string]$InstallRoot = 'C:\temp\o365audit'
)

# Deliberately NOT 'Stop': native commands write status text to stderr, which would
# otherwise abort the probe before it can report an exit code.
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

Write-Host "whoami : $(whoami)"
Write-Host "psexec : $psexec ($((Get-Item $psexec).VersionInfo.FileVersion))"
Write-Host "target : $Target"
Write-Host ""

$escapedPath = $remoteScriptPath.Replace("'", "''")
$inner = "`$p='$escapedPath';`$e='$remoteScriptSha256';" +
         "`$a=(Get-FileHash -LiteralPath `$p -Algorithm SHA256 -ErrorAction Stop).Hash;" +
         "if(-not [String]::Equals(`$a,`$e,[StringComparison]::OrdinalIgnoreCase)){throw 'Collector integrity validation failed.'};& `$p"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$collectorArgs = "\\$Target -nobanner -accepteula -h -s powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
$echoArgs = "\\$Target -nobanner -accepteula -h -s cmd /c echo COLLECTOR_PROBE_OK"

$work = Join-Path ([IO.Path]::GetTempPath()) ("psxmode-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Read-TextFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    try {
        $text = [IO.File]::ReadAllText($Path)
        if ($null -eq $text) { return '' }
        return $text
    }
    catch { return '' }
}

function Write-BatchFile {
    param([string]$Path, [string]$PsExecArguments, [string]$OutFile, [string]$ErrFile)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('@echo off')
    $lines.Add(('"{0}" {1} > "{2}" 2> "{3}"' -f $psexec, $PsExecArguments, $OutFile, $ErrFile))
    $lines.Add('exit /b %ERRORLEVEL%')
    [IO.File]::WriteAllLines($Path, $lines, [Text.Encoding]::ASCII)
}

function Report-Mode {
    param([string]$Name, [string]$Description, $Exit, [string]$Stdout, [string]$Stderr, [string]$Note)

    $out = if ($null -eq $Stdout) { '' } else { [string]$Stdout }
    $err = if ($null -eq $Stderr) { '' } else { [string]$Stderr }
    $combined = $out + "`n" + $err

    $captured = $out.Contains('COLLECTOR_PROBE_OK') -or $out.Contains('"schemaVersion"')
    $handleInvalid = $combined -match '(?i)handle is invalid'

    $color = if ($Exit -eq 0 -and $captured) { 'Green' } elseif ($Exit -eq 0) { 'Yellow' } else { 'Red' }
    Write-Host ("{0,-14} {1,-30} exit={2,-6} cikti={3,-6} handleInvalid={4,-6} {5}" -f `
        $Name, $Description, $Exit, $captured, $handleInvalid, $Note) -ForegroundColor $color

    if (-not [string]::IsNullOrWhiteSpace($err)) {
        $preview = $err.Trim()
        if ($preview.Length -gt 180) { $preview = $preview.Substring(0, 180) + ' ...' }
        Write-Host ("               stderr: " + ($preview -replace "`r?`n", ' | ')) -ForegroundColor DarkGray
    }
}

function Invoke-PipesMode {
    param([string]$Name, [string]$PsExecArguments)
    # What the service does today: all three streams on pipes, no console.
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
        $null = $p.WaitForExit(300000)
        $code = $p.ExitCode
        $so = [string]$o.Result
        $se = [string]$e.Result
        $p.Dispose()
        Report-Mode -Name $Name -Description '.NET pipes (mevcut)' -Exit $code -Stdout $so -Stderr $se
    }
    catch {
        Report-Mode -Name $Name -Description '.NET pipes (mevcut)' -Exit 'HATA' -Note $_.Exception.Message
    }
}

function Invoke-BatchMode {
    param([string]$Name, [string]$Description, [string]$PsExecArguments, [switch]$UseStart)
    try {
        $batch = Join-Path $work "$Name.cmd"
        $outFile = Join-Path $work "$Name.out"
        $errFile = Join-Path $work "$Name.err"
        Write-BatchFile -Path $batch -PsExecArguments $PsExecArguments -OutFile $outFile -ErrFile $errFile

        if ($UseStart) {
            # New console via "start", output already redirected to files by the batch.
            $cmdLine = 'start "" /wait "' + $batch + '"'
        }
        else {
            $cmdLine = '"' + $batch + '"'
        }

        $null = & cmd.exe /s /c $cmdLine 2>&1
        $code = $LASTEXITCODE

        Report-Mode -Name $Name -Description $Description -Exit $code `
            -Stdout (Read-TextFile $outFile) -Stderr (Read-TextFile $errFile)
    }
    catch {
        Report-Mode -Name $Name -Description $Description -Exit 'HATA' -Note $_.Exception.Message
    }
}

try {
    Write-Host "--- Basit uzak komut (echo) ---" -ForegroundColor Cyan
    Invoke-PipesMode -Name 'E1-pipes'     -PsExecArguments $echoArgs
    Invoke-BatchMode -Name 'E2-batch'     -Description 'batch, start YOK'      -PsExecArguments $echoArgs
    Invoke-BatchMode -Name 'E3-startwait' -Description 'batch + start /wait'   -PsExecArguments $echoArgs -UseStart

    Write-Host ""
    Write-Host "--- Gercek collector cagrisi ---" -ForegroundColor Cyan
    Invoke-BatchMode -Name 'C3-startwait' -Description 'batch + start /wait'   -PsExecArguments $collectorArgs -UseStart

    Write-Host ""
    Write-Host "Aranan: 'startwait' satirlarinda exit=0 ve cikti=True." -ForegroundColor Cyan
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
