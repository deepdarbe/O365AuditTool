[CmdletBinding()]
param(
    [string]$BundleUri = "",

    [string]$ExpectedSha256 = "",
    [string]$ChecksumUri = "",
    [hashtable]$DownloadHeaders = @{},
    [switch]$AllowInsecureHttp,
    [switch]$KeepBootstrapFiles,

    [string]$InstallRoot = 'C:\temp\o365audit',
    [string]$ServiceName = 'O365AuditTool',
    [ValidateRange(1, 65535)]
    [int]$Port = 5080,
    [ValidateRange(1, 65535)]
    [int]$HealthPort = 5081,
    [string]$DashboardDnsName = "",
    [string]$TlsCertificateThumbprint = "",
    [switch]$AllowInsecureHttpDashboard,
    [switch]$AutoConfigure,
    [string]$PsExecPath = 'C:\Tools\PsExec\PsExec64.exe',
    [bool]$DownloadPsExecIfMissing = $true,
    # Ranges mirror Deploy-ManagementServer.ps1 so a bad value is refused here, before the bundle is
    # downloaded and the service is stopped. [bool] and not [switch] for ReachabilityProbeEnabled:
    # the service default is TRUE and an omitted switch would forward FALSE.
    [ValidateRange(1, 600)]
    [int]$PsExecConnectTimeoutSeconds = 30,
    [bool]$ReachabilityProbeEnabled = $true,
    [ValidateRange(1, 65535)]
    [int]$ReachabilityProbePort = 445,
    [ValidateRange(1, 60)]
    [int]$ReachabilityProbeTimeoutSeconds = 5,
    [string]$CollectorSharePath = '',
    [string]$CollectorShareName = 'o365audit',
    [string]$DomainComputersGroup = "",
    [string[]]$FallbackTargets = @(),
    [string]$DefaultOuFilter = "",
    [string]$DefaultSiteFilter = "",
    [string[]]$ExcludeDeviceNames = @(),
    [string[]]$ExcludeOus = @(),
    # Both default TRUE in CollectorOptions; a [switch] left off would forward FALSE and put every
    # server and domain controller back into the nightly scan.
    [bool]$ExcludeServerOperatingSystems = $true,
    [bool]$ExcludeDomainControllers = $true,
    [switch]$ExcludeUnknownOperatingSystem,
    [string[]]$AuditAdminGroups = @(),
    [string[]]$AuditReaderGroups = @(),
    [string[]]$MigrationPlannerGroups = @(),
    [string]$GmsaAccount = "",
    [PSCredential]$ServiceCredential,
    [switch]$AllowLocalSystem,
    [switch]$EnableArtifactCopy,
    [switch]$DisableArtifactCopy,
    [string]$CopyTargetRoot = "",
    [string[]]$AllowedCopyTargetRoots = @(),
    [string[]]$AllowedCopySourceUncRoots = @(),
    [switch]$CopyVerifySha256,
    [switch]$DisableCopySha256,
    [switch]$FunctionsOnly
)

$ErrorActionPreference = 'Stop'
if ($CopyVerifySha256 -and $DisableCopySha256) {
    throw 'CopyVerifySha256 ve DisableCopySha256 birlikte kullanilamaz.'
}
if ($EnableArtifactCopy -and $DisableArtifactCopy) {
    throw 'EnableArtifactCopy ve DisableArtifactCopy birlikte kullanilamaz.'
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Bootstrap Administrator yetkisi ile calistirilmalidir."
    }
}

function Assert-NoReparsePointInPath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    $current = $root
    foreach ($segment in $fullPath.Substring($root.Length).Split([char[]]'\/', [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            continue
        }

        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Bootstrap path reparse point iceremez: '$current'."
        }
    }
}

function New-PrivateDirectoryAcl {
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($administratorsSid, $systemSid, $currentSid)) {
        $null = $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $none,
            $allow)))
    }

    return $acl
}

function New-DirectoryWithAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Acl
    )

    $directoryInfo = New-Object IO.DirectoryInfo($Path)
    $aclOverload = [IO.DirectoryInfo].GetMethods() |
        Where-Object {
            $_.Name -eq 'Create' -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType -eq [Security.AccessControl.DirectorySecurity]
        } |
        Select-Object -First 1
    if ($null -ne $aclOverload) {
        $directoryInfo.Create($Acl)
        return
    }

    [IO.FileSystemAclExtensions]::CreateDirectory($Acl, $Path) | Out-Null
}

function Set-DirectoryAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Acl
    )

    $directoryInfo = New-Object IO.DirectoryInfo($Path)
    $setAclMethod = [IO.DirectoryInfo].GetMethods() |
        Where-Object {
            $_.Name -eq 'SetAccessControl' -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType -eq [Security.AccessControl.DirectorySecurity]
        } |
        Select-Object -First 1
    if ($null -ne $setAclMethod) {
        $directoryInfo.SetAccessControl($Acl)
        return
    }

    [IO.FileSystemAclExtensions]::SetAccessControl($directoryInfo, $Acl)
}

function Initialize-PrivateDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $parent = Split-Path $Path -Parent
    Assert-NoReparsePointInPath -Path $parent
    $acl = New-PrivateDirectoryAcl
    if (Test-Path -LiteralPath $Path) {
        Assert-NoReparsePointInPath -Path $Path
        Set-DirectoryAcl -Path $Path -Acl $acl
    }
    else {
        New-DirectoryWithAcl -Path $Path -Acl $acl
    }
    Assert-NoReparsePointInPath -Path $Path
    Set-DirectoryAcl -Path $Path -Acl $acl
}

function Assert-DownloadLocation {
    param(
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$Name
    )

    if (Test-Path -LiteralPath $Location -PathType Leaf) {
        return
    }

    [Uri]$uri = $null
    if (-not [Uri]::TryCreate($Location, [UriKind]::Absolute, [ref]$uri)) {
        throw "$Name gecerli bir HTTPS adresi veya yerel dosya degil: '$Location'."
    }
    if ($uri.Scheme -eq 'https') {
        return
    }
    if ($uri.Scheme -eq 'http' -and $AllowInsecureHttp) {
        return
    }

    throw "$Name icin HTTPS zorunludur. Bilincli HTTP istisnasi icin -AllowInsecureHttp kullanin."
}

function Receive-File {
    param(
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$Destination,
        [hashtable]$Headers = @{}
    )

    if (Test-Path -LiteralPath $Location -PathType Leaf) {
        Copy-Item -LiteralPath $Location -Destination $Destination -Force
        return
    }

    Invoke-WebRequest -Uri $Location -OutFile $Destination -UseBasicParsing -Headers $Headers
}

function Get-ExpectedHash {
    param(
        [string]$ExplicitHash,
        [string]$HashLocation,
        [string]$DownloadDirectory
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitHash)) {
        $hash = $ExplicitHash.Trim().ToUpperInvariant()
    }
    elseif (-not [string]::IsNullOrWhiteSpace($HashLocation)) {
        Assert-DownloadLocation -Location $HashLocation -Name 'ChecksumUri'
        $checksumFile = Join-Path $DownloadDirectory 'bundle.sha256'
        Receive-File -Location $HashLocation -Destination $checksumFile -Headers $DownloadHeaders
        $checksumText = Get-Content -LiteralPath $checksumFile -Raw
        $match = [regex]::Match($checksumText, '(?i)\b[0-9a-f]{64}\b')
        if (-not $match.Success) {
            throw "ChecksumUri gecerli bir SHA256 icermiyor."
        }
        $hash = $match.Value.ToUpperInvariant()
    }
    else {
        throw "Fail-closed kurulum icin -ExpectedSha256 veya -ChecksumUri zorunludur."
    }

    if ($hash -notmatch '^[0-9A-F]{64}$') {
        throw "ExpectedSha256 64 karakterlik hexadecimal SHA256 olmalidir."
    }
    return $hash
}

function Assert-MicrosoftSignedFile {
    param([Parameter(Mandatory)][string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Dosya imzasi gecerli degil: '$Path' ($($signature.Status))."
    }
    if ($signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') {
        throw "Dosya Microsoft Corporation tarafindan imzalanmamis: '$Path'."
    }
}

function Install-PsExecIfNeeded {
    param(
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][string]$DownloadDirectory
    )

    if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
        Assert-MicrosoftSignedFile -Path $DestinationPath
        return
    }
    if (-not $DownloadPsExecIfMissing) {
        throw "PsExec bulunamadi: '$DestinationPath'."
    }

    $psToolsUri = 'https://download.sysinternals.com/files/PSTools.zip'
    $psToolsArchive = Join-Path $DownloadDirectory 'PSTools.zip'
    $psToolsExtract = Join-Path $DownloadDirectory 'PSTools'
    Invoke-WebRequest -Uri $psToolsUri -OutFile $psToolsArchive -UseBasicParsing
    Expand-Archive -LiteralPath $psToolsArchive -DestinationPath $psToolsExtract -Force

    $downloadedPsExec = Join-Path $psToolsExtract 'PsExec64.exe'
    if (-not (Test-Path -LiteralPath $downloadedPsExec -PathType Leaf)) {
        throw "Resmi PsTools paketinde PsExec64.exe bulunamadi."
    }
    Assert-MicrosoftSignedFile -Path $downloadedPsExec

    $destinationDirectory = Split-Path $DestinationPath -Parent
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item -LiteralPath $downloadedPsExec -Destination $DestinationPath -Force
    Assert-MicrosoftSignedFile -Path $DestinationPath
}

function Assert-BundleManifest {
    param(
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)]$Manifest
    )

    if ($Manifest.SchemaVersion -ne '1.0' -or $Manifest.Product -ne 'O365AuditTool') {
        throw "Release manifest urun veya sema bilgisi gecersiz."
    }

    $normalizedRoot = [IO.Path]::GetFullPath($BundleRoot).TrimEnd('\') + '\'
    foreach ($file in @($Manifest.Files)) {
        $relativePath = ([string]$file.Path).Replace('/', '\')
        $fullPath = [IO.Path]::GetFullPath((Join-Path $BundleRoot $relativePath))
        if (-not $fullPath.StartsWith($normalizedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Manifest path bundle disina cikiyor: '$relativePath'."
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Manifest dosyasi eksik: '$relativePath'."
        }

        $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
        if (-not $actualHash.Equals([string]$file.Sha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Manifest dosya hash dogrulamasi basarisiz: '$relativePath'."
        }
    }
}

if ($FunctionsOnly) { return }
if ([string]::IsNullOrWhiteSpace($BundleUri)) {
    throw 'BundleUri zorunludur.'
}

Assert-Administrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Assert-DownloadLocation -Location $BundleUri -Name 'BundleUri'
$PsExecPath = [IO.Path]::GetFullPath($PsExecPath)

$bootstrapProductRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'O365AuditTool'))
Initialize-PrivateDirectory -Path $bootstrapProductRoot
$bootstrapParent = Join-Path $bootstrapProductRoot 'bootstrap'
Initialize-PrivateDirectory -Path $bootstrapParent
$bootstrapRoot = Join-Path $bootstrapParent ([Guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $bootstrapRoot 'O365AuditTool.zip'
$extractPath = Join-Path $bootstrapRoot 'extracted'

try {
    Initialize-PrivateDirectory -Path $bootstrapRoot
    $expectedHash = Get-ExpectedHash `
        -ExplicitHash $ExpectedSha256 `
        -HashLocation $ChecksumUri `
        -DownloadDirectory $bootstrapRoot

    Receive-File -Location $BundleUri -Destination $archivePath -Headers $DownloadHeaders
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToUpperInvariant()
    if (-not $actualHash.Equals($expectedHash, [StringComparison]::Ordinal)) {
        throw "Bundle SHA256 dogrulamasi basarisiz. Expected=$expectedHash Actual=$actualHash"
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force
    $manifestPath = Join-Path $extractPath 'release-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "release-manifest.json bundle icinde bulunamadi."
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Assert-BundleManifest -BundleRoot $extractPath -Manifest $manifest

    $deployScript = Join-Path $extractPath 'scripts\Deploy-ManagementServer.ps1'
    $collectorScript = Join-Path $extractPath 'scripts\collector.ps1'
    $publishedApp = Join-Path $extractPath 'app'
    Install-PsExecIfNeeded -DestinationPath $PsExecPath -DownloadDirectory $bootstrapRoot

    $deployArguments = @{
        PublishedAppPath = $publishedApp
        CollectorPath = $collectorScript
        InstallRoot = $InstallRoot
        ServiceName = $ServiceName
        PsExecPath = $PsExecPath
    }
    foreach ($parameterName in @(
        'Port',
        'HealthPort',
        'DashboardDnsName',
        'TlsCertificateThumbprint',
        'PsExecConnectTimeoutSeconds',
        'ReachabilityProbeEnabled',
        'ReachabilityProbePort',
        'ReachabilityProbeTimeoutSeconds',
        'CollectorSharePath',
        'CollectorShareName',
        'DomainComputersGroup',
        'FallbackTargets',
        'DefaultOuFilter',
        'DefaultSiteFilter',
        'ExcludeDeviceNames',
        'ExcludeOus',
        'ExcludeServerOperatingSystems',
        'ExcludeDomainControllers',
        'ExcludeUnknownOperatingSystem',
        'AuditAdminGroups',
        'AuditReaderGroups',
        'MigrationPlannerGroups',
        'GmsaAccount',
        'CopyTargetRoot',
        'AllowedCopyTargetRoots',
        'AllowedCopySourceUncRoots'
    )) {
        if ($PSBoundParameters.ContainsKey($parameterName)) {
            $deployArguments[$parameterName] = Get-Variable -Name $parameterName -ValueOnly
        }
    }
    if ($PSBoundParameters.ContainsKey('ServiceCredential')) {
        $deployArguments.ServiceCredential = $ServiceCredential
    }
    if ($AllowLocalSystem) {
        $deployArguments.AllowLocalSystem = $true
    }
    if ($AllowInsecureHttpDashboard) {
        $deployArguments.AllowInsecureHttpDashboard = $true
    }
    if ($AutoConfigure) {
        $deployArguments.AutoConfigure = $true
    }
    if ($EnableArtifactCopy) {
        $deployArguments.EnableArtifactCopy = $true
    }
    if ($DisableArtifactCopy) {
        $deployArguments.DisableArtifactCopy = $true
    }
    if ($CopyVerifySha256) {
        $deployArguments.CopyVerifySha256 = $true
    }
    if ($DisableCopySha256) {
        $deployArguments.DisableCopySha256 = $true
    }

    Assert-NoReparsePointInPath -Path $extractPath
    Assert-BundleManifest -BundleRoot $extractPath -Manifest $manifest
    & $deployScript @deployArguments
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "Deployment script hata kodu ile tamamlandi: $LASTEXITCODE."
    }

    Write-Host "Bootstrap kurulum tamamlandi. Bundle SHA256: $actualHash" -ForegroundColor Green
}
finally {
    if (-not $KeepBootstrapFiles) {
        $resolvedBootstrap = [IO.Path]::GetFullPath($bootstrapRoot)
        $expectedPrefix = $bootstrapParent.TrimEnd('\') + '\'
        if (
            $resolvedBootstrap.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path $resolvedBootstrap -Leaf) -match '^[0-9a-f]{32}$' -and
            (Test-Path -LiteralPath $resolvedBootstrap)
        ) {
            Remove-Item -LiteralPath $resolvedBootstrap -Recurse -Force
        }
    }
}
