[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.-]{0,63}$')]
    [string]$Version,

    [string]$OutputDirectory = "",

    [ValidateSet('win-x64')]
    [string]$Runtime = 'win-x64',

    [string]$DotNetPath = "",

    [switch]$AllowDirtyWorktree
)

$ErrorActionPreference = 'Stop'

function Get-RelativePath {
    param(
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$Path
    )

    $getRelativePath = [IO.Path].GetMethods() |
        Where-Object { $_.Name -eq 'GetRelativePath' -and $_.GetParameters().Count -eq 2 } |
        Select-Object -First 1
    if ($null -ne $getRelativePath) {
        return [IO.Path]::GetRelativePath($BasePath, $Path).Replace('\', '/')
    }

    # Windows PowerShell 5.1 runs on .NET Framework, where Path.GetRelativePath is absent.
    $baseFullPath = [IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'
    $pathFullPath = [IO.Path]::GetFullPath($Path)
    $baseUri = New-Object Uri($baseFullPath)
    $pathUri = New-Object Uri($pathFullPath)
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString())
}

function Resolve-DotNet10SdkPath {
    param([string]$ExplicitPath)

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $candidates += $ExplicitPath
    }
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $candidates += $command.Source
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates += (Join-Path $env:USERPROFILE '.dotnet\dotnet.exe')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates += (Join-Path $env:ProgramFiles 'dotnet\dotnet.exe')
    }

    foreach ($candidate in ($candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        $resolved = [IO.Path]::GetFullPath($candidate)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            continue
        }

        $versionOutput = @(& $resolved --version 2>$null)
        $versionExitCode = $LASTEXITCODE
        $version = $versionOutput | Select-Object -First 1
        if ($versionExitCode -eq 0 -and ([string]$version) -match '^10\.\d+\.\d+') {
            return $resolved
        }
    }

    throw '.NET 10 SDK bulunamadi. -DotNetPath ile dotnet.exe konumunu belirtin veya %USERPROFILE%\.dotnet altina kurun.'
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$releaseInputs = @(
    'src/O365AuditTool',
    'scripts/Deploy-ManagementServer.ps1',
    'scripts/collector.ps1',
    'scripts/Get-O365AuditDiagnostics.ps1',
    'scripts/Install-O365AuditTool.ps1',
    'scripts/Invoke-CollectorAccessDiagnostic.ps1',
    'scripts/New-O365AuditRelease.ps1'
)
if (-not $AllowDirtyWorktree) {
    $worktreeStatus = @(& git -C $repoRoot status --porcelain --untracked-files=all -- @releaseInputs 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'Release provenance dogrulanamadi: git worktree durumu okunamadi.'
    }
    if ($worktreeStatus.Count -gt 0) {
        throw "Release girdileri commit edilmemis degisiklik iceriyor. Once commit edin veya yalniz yerel test icin -AllowDirtyWorktree kullanin: $($worktreeStatus -join '; ')"
    }
}
$dotnet = Resolve-DotNet10SdkPath -ExplicitPath $DotNetPath
$projectPath = Join-Path $repoRoot 'src\O365AuditTool\O365AuditTool.csproj'
if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
    throw "O365AuditTool.csproj bulunamadi: '$projectPath'."
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot 'artifacts\o365audit-release'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$stagingParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$stagingRoot = Join-Path $stagingParent "o365audit-release-$([Guid]::NewGuid().ToString('N'))"
$bundleRoot = Join-Path $stagingRoot 'bundle'
$appRoot = Join-Path $bundleRoot 'app'
$scriptsRoot = Join-Path $bundleRoot 'scripts'
$archiveName = "O365AuditTool-$Version-$Runtime.zip"
$archivePath = Join-Path $OutputDirectory $archiveName
$checksumPath = "$archivePath.sha256"
$bootstrapName = "Install-O365AuditTool-$Version.ps1"
$bootstrapPath = Join-Path $OutputDirectory $bootstrapName
$bootstrapChecksumPath = "$bootstrapPath.sha256"

try {
    New-Item -ItemType Directory -Path $appRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $scriptsRoot -Force | Out-Null

    & $dotnet publish $projectPath `
        -c Release `
        -r $Runtime `
        --self-contained true `
        -p:Version=$Version `
        -p:InformationalVersion=$Version `
        -p:PublishSingleFile=false `
        -p:PublishTrimmed=false `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -o $appRoot
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish hata kodu ile tamamlandi: $LASTEXITCODE."
    }

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Deploy-ManagementServer.ps1') `
        -Destination (Join-Path $scriptsRoot 'Deploy-ManagementServer.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'collector.ps1') `
        -Destination (Join-Path $scriptsRoot 'collector.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Get-O365AuditDiagnostics.ps1') `
        -Destination (Join-Path $scriptsRoot 'Get-O365AuditDiagnostics.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-CollectorAccessDiagnostic.ps1') `
        -Destination (Join-Path $scriptsRoot 'Invoke-CollectorAccessDiagnostic.ps1') -Force

    $commit = 'uncommitted'
    try {
        $candidate = (& git -C $repoRoot rev-parse HEAD 2>$null | Select-Object -First 1)
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $commit = $candidate.Trim()
        }
    }
    catch {}

    $files = @(
        Get-ChildItem -LiteralPath $bundleRoot -Recurse -File |
            Sort-Object FullName |
            ForEach-Object {
                @{
                    Path = Get-RelativePath -BasePath $bundleRoot -Path $_.FullName
                    SizeBytes = [int64]$_.Length
                    Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                }
            }
    )

    $manifest = @{
        SchemaVersion = '1.0'
        Product = 'O365AuditTool'
        Version = $Version
        Runtime = $Runtime
        SelfContained = $true
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
        Commit = $commit
        Files = $files
    }
    $manifestPath = Join-Path $bundleRoot 'release-manifest.json'
    $manifest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $manifestPath -Encoding utf8

    if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
        [IO.File]::Delete($archivePath)
    }
    if (Test-Path -LiteralPath $checksumPath -PathType Leaf) {
        [IO.File]::Delete($checksumPath)
    }
    if (Test-Path -LiteralPath $bootstrapPath -PathType Leaf) {
        [IO.File]::Delete($bootstrapPath)
    }
    if (Test-Path -LiteralPath $bootstrapChecksumPath -PathType Leaf) {
        [IO.File]::Delete($bootstrapChecksumPath)
    }

    Compress-Archive -Path (Join-Path $bundleRoot '*') -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToUpperInvariant()
    "$archiveHash  $archiveName" | Set-Content -LiteralPath $checksumPath -Encoding ascii
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-O365AuditTool.ps1') -Destination $bootstrapPath
    $bootstrapHash = (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256).Hash.ToUpperInvariant()
    "$bootstrapHash  $bootstrapName" | Set-Content -LiteralPath $bootstrapChecksumPath -Encoding ascii

    [pscustomobject]@{
        Version = $Version
        Runtime = $Runtime
        ArchivePath = $archivePath
        ChecksumPath = $checksumPath
        Sha256 = $archiveHash
        BootstrapPath = $bootstrapPath
        BootstrapChecksumPath = $bootstrapChecksumPath
        BootstrapSha256 = $bootstrapHash
    }
}
finally {
    $resolvedStaging = [IO.Path]::GetFullPath($stagingRoot)
    if (
        $resolvedStaging.StartsWith($stagingParent, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path $resolvedStaging -Leaf) -like 'o365audit-release-*' -and
        (Test-Path -LiteralPath $resolvedStaging)
    ) {
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
