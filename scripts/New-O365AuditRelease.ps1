[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.-]{0,63}$')]
    [string]$Version,

    [string]$OutputDirectory = "",

    [ValidateSet('win-x64')]
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'

function Get-RelativePath {
    param(
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$Path
    )

    return [IO.Path]::GetRelativePath($BasePath, $Path).Replace('\', '/')
}

$repoRoot = Split-Path $PSScriptRoot -Parent
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

try {
    New-Item -ItemType Directory -Path $appRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $scriptsRoot -Force | Out-Null

    & dotnet publish $projectPath `
        -c Release `
        -r $Runtime `
        --self-contained true `
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

    Compress-Archive -Path (Join-Path $bundleRoot '*') -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToUpperInvariant()
    "$archiveHash  $archiveName" | Set-Content -LiteralPath $checksumPath -Encoding ascii

    [pscustomobject]@{
        Version = $Version
        Runtime = $Runtime
        ArchivePath = $archivePath
        ChecksumPath = $checksumPath
        Sha256 = $archiveHash
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
