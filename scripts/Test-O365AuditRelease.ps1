[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ArchivePath,

    [string]$ExpectedSha256 = "",
    [string]$ChecksumPath = ""
)

$ErrorActionPreference = 'Stop'

$ArchivePath = [IO.Path]::GetFullPath($ArchivePath)
if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
    throw "Release archive bulunamadi: '$ArchivePath'."
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    $expectedHash = $ExpectedSha256.Trim().ToUpperInvariant()
}
else {
    if ([string]::IsNullOrWhiteSpace($ChecksumPath)) {
        $ChecksumPath = "$ArchivePath.sha256"
    }
    $ChecksumPath = [IO.Path]::GetFullPath($ChecksumPath)
    if (-not (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
        throw "Checksum dosyasi bulunamadi: '$ChecksumPath'."
    }
    $checksumText = Get-Content -LiteralPath $ChecksumPath -Raw
    $match = [regex]::Match($checksumText, '(?i)\b[0-9a-f]{64}\b')
    if (-not $match.Success) {
        throw "Checksum dosyasi gecerli bir SHA256 icermiyor."
    }
    $expectedHash = $match.Value.ToUpperInvariant()
}

if ($expectedHash -notmatch '^[0-9A-F]{64}$') {
    throw "ExpectedSha256 64 karakterlik hexadecimal SHA256 olmalidir."
}

$actualHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToUpperInvariant()
if (-not $actualHash.Equals($expectedHash, [StringComparison]::Ordinal)) {
    throw "Archive SHA256 dogrulamasi basarisiz. Expected=$expectedHash Actual=$actualHash"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
try {
    $entries = @{}
    foreach ($entry in $archive.Entries) {
        $entryPath = $entry.FullName.Replace('\', '/')
        if ($entries.ContainsKey($entryPath)) {
            throw "Release archive yinelenen entry iceriyor: '$entryPath'."
        }
        $entries[$entryPath] = $entry
    }

    foreach ($required in @(
        'app/O365AuditTool.exe',
        'app/O365AuditTool.dll',
        'scripts/Deploy-ManagementServer.ps1',
        'scripts/collector.ps1',
        'scripts/Get-O365AuditDiagnostics.ps1',
        'release-manifest.json'
    )) {
        if (-not $entries.ContainsKey($required)) {
            throw "Release archive zorunlu dosyayi icermiyor: '$required'."
        }
    }

    $reader = New-Object IO.StreamReader($entries['release-manifest.json'].Open())
    try {
        $manifest = $reader.ReadToEnd() | ConvertFrom-Json
    }
    finally {
        $reader.Dispose()
    }

    if (
        $manifest.SchemaVersion -ne '1.0' -or
        $manifest.Product -ne 'O365AuditTool' -or
        -not [bool]$manifest.SelfContained
    ) {
        throw "Release manifest urun, sema veya self-contained bilgisi gecersiz."
    }

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $manifestPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($manifest.Files)) {
            $entryPath = ([string]$file.Path).Replace('\', '/')
            if (-not $manifestPaths.Add($entryPath)) {
                throw "Manifest yinelenen dosya iceriyor: '$entryPath'."
            }
            if (-not $entries.ContainsKey($entryPath)) {
                throw "Manifest dosyasi archive icinde eksik: '$entryPath'."
            }

            $stream = $entries[$entryPath].Open()
            try {
                $fileHash = ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
            }
            finally {
                $stream.Dispose()
            }

            if (-not $fileHash.Equals([string]$file.Sha256, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Manifest dosya hash dogrulamasi basarisiz: '$entryPath'."
            }
        }

        $unexpectedEntries = @(
            $archive.Entries |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_.Name) -and
                    $_.FullName.Replace('\', '/') -ne 'release-manifest.json' -and
                    -not $manifestPaths.Contains($_.FullName.Replace('\', '/'))
                } |
                ForEach-Object { $_.FullName.Replace('\', '/') }
        )
        if ($unexpectedEntries.Count -gt 0) {
            throw "Release archive manifest disi dosya iceriyor: $($unexpectedEntries -join ', ')"
        }
    }
    finally {
        $sha256.Dispose()
    }

    [pscustomobject]@{
        Product = $manifest.Product
        Version = $manifest.Version
        Runtime = $manifest.Runtime
        SelfContained = [bool]$manifest.SelfContained
        FileCount = @($manifest.Files).Count
        ArchiveBytes = (Get-Item -LiteralPath $ArchivePath).Length
        Sha256 = $actualHash
    }
}
finally {
    $archive.Dispose()
}
