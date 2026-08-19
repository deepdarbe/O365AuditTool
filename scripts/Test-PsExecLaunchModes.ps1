<#
.SYNOPSIS
    Measures which PsExec launch mode works from a session-0 service context and
    still lets the caller capture stdout/stderr and the exit code.

.DESCRIPTION
    The collector launches PsExec from a Windows service (session 0). In that
    context PsExec fails with "Couldn't access <host>: The handle is invalid."
    (exit 6) unless it gets a real console. Redirecting the standard streams to
    pipes suppresses console allocation, so the fix has to both give PsExec a
    console AND still capture its output.

    Run this ON the management server, as SYSTEM, e.g.:

        psexec.exe -accepteula -nobanner -s powershell -NoProfile `
            -ExecutionPolicy Bypass -File C:\temp\Test-PsExecLaunchModes.ps1 -Target CORELAPP

    It reports, for each candidate launch mode, the exit code and whether the
    remote output was captured. The mode that returns 0 AND captures output is
    the one to implement in PsExecCollectorRunner.

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

$ErrorActionPreference = 'Stop'

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

Write-Host "whoami        : $(whoami)"
Write-Host "psexec        : $psexec ($((Get-Item $psexec).VersionInfo.FileVersion))"
Write-Host "target        : $Target"
Write-Host ""

# The exact collector payload command the service runs.
$escapedPath = $remoteScriptPath.Replace("'", "''")
$inner = "`$p='$escapedPath';`$e='$remoteScriptSha256';" +
         "`$a=(Get-FileHash -LiteralPath `$p -Algorithm SHA256 -ErrorAction Stop).Hash;" +
         "if(-not [String]::Equals(`$a,`$e,[StringComparison]::OrdinalIgnoreCase)){throw 'Collector integrity validation failed.'};& `$p"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$collectorArgs = "\\$Target -nobanner -accepteula -h -s powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
$echoArgs = "\\$Target -nobanner -accepteula -h -s cmd /c echo COLLECTOR_PROBE_OK"

$work = Join-Path ([IO.Path]::GetTempPath()) ("psxmode-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Invoke-Mode {
    param(
        [string]$Name,
        [string]$Description,
        [string]$PsExecArguments,
        [ValidateSet('DotNetPipes', 'BatchStartWait', 'BatchDirect')]
        [string]$Mode
    )

    $outFile = Join-Path $work "$Name.out"
    $errFile = Join-Path $work "$Name.err"
    $exit = $null
    $note = ''

    try {
        switch ($Mode) {
            'DotNetPipes' {
                # What the service does today: redirected pipes, no console.
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
                $exit = $p.ExitCode
                Set-Content -LiteralPath $outFile -Value $o.Result
                Set-Content -LiteralPath $errFile -Value $e.Result
                $p.Dispose()
            }
            'BatchStartWait' {
                # Candidate fix: a new console via "start /wait", output to files.
                $batch = Join-Path $work "$Name.cmd"
                $lines = @(
                    '@echo off',
                    ('"{0}" {1} > "{2}" 2> "{3}"' -f $psexec, $PsExecArguments, $outFile, $errFile),
                    'exit /b %ERRORLEVEL%'
                )
                Set-Content -LiteralPath $batch -Value $lines -Encoding OEM
                & cmd.exe /s /c "start `"`" /wait `"$batch`""
                $exit = $LASTEXITCODE
            }
            'BatchDirect' {
                # Control: same batch, but without "start" (no new console).
                $batch = Join-Path $work "$Name.cmd"
                $lines = @(
                    '@echo off',
                    ('"{0}" {1} > "{2}" 2> "{3}"' -f $psexec, $PsExecArguments, $outFile, $errFile),
                    'exit /b %ERRORLEVEL%'
                )
                Set-Content -LiteralPath $batch -Value $lines -Encoding OEM
                & cmd.exe /s /c "`"$batch`""
                $exit = $LASTEXITCODE
            }
        }
    }
    catch {
        $note = "EXCEPTION: $($_.Exception.Message)"
    }

    $stdout = ''
    $stderr = ''
    if (Test-Path -LiteralPath $outFile) { $stdout = [string](Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue) }
    if (Test-Path -LiteralPath $errFile) { $stderr = [string](Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue) }

    $captured = $stdout.Contains('COLLECTOR_PROBE_OK') -or $stdout.Contains('"schemaVersion"')
    $handleInvalid = ($stdout + $stderr) -match '(?i)handle is invalid'

    $color = if ($exit -eq 0 -and $captured) { 'Green' } elseif ($exit -eq 0) { 'Yellow' } else { 'Red' }
    Write-Host ("{0,-16} {1,-34} exit={2,-6} cikti={3,-5} handleInvalid={4} {5}" -f `
        $Name, $Description, $exit, $captured, $handleInvalid, $note) -ForegroundColor $color

    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        $preview = $stderr.Trim()
        if ($preview.Length -gt 200) { $preview = $preview.Substring(0, 200) + ' ...' }
        Write-Host ("                 stderr: " + ($preview -replace "`r?`n", ' | ')) -ForegroundColor DarkGray
    }
}

try {
    Write-Host "--- Basit uzak komut (echo) ---" -ForegroundColor Cyan
    Invoke-Mode -Name 'E1-pipes'      -Description '.NET pipes (mevcut v1.2.8)'  -PsExecArguments $echoArgs -Mode DotNetPipes
    Invoke-Mode -Name 'E2-batchdirek' -Description 'batch, start YOK'            -PsExecArguments $echoArgs -Mode BatchDirect
    Invoke-Mode -Name 'E3-startwait'  -Description 'batch + start /wait (aday)'  -PsExecArguments $echoArgs -Mode BatchStartWait

    Write-Host ""
    Write-Host "--- Gercek collector cagrisi ---" -ForegroundColor Cyan
    Invoke-Mode -Name 'C1-pipes'      -Description '.NET pipes (mevcut v1.2.8)'  -PsExecArguments $collectorArgs -Mode DotNetPipes
    Invoke-Mode -Name 'C3-startwait'  -Description 'batch + start /wait (aday)'  -PsExecArguments $collectorArgs -Mode BatchStartWait

    Write-Host ""
    Write-Host "Beklenen: 'startwait' satirlarinda exit=0 ve cikti=True." -ForegroundColor Cyan
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
