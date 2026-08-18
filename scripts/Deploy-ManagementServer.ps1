[CmdletBinding()]
param(
    [string]$ProjectPath = "",
    [string]$PublishedAppPath = "",
    [string]$CollectorPath = "",
    [string]$InstallRoot = "C:\temp\o365audit",
    [string]$ServiceName = "O365AuditTool",
    [ValidateRange(1, 65535)]
    [int]$Port = 5080,
    [ValidateRange(1, 65535)]
    [int]$HealthPort = 5081,
    [string]$DashboardDnsName = "",
    [string]$TlsCertificateThumbprint = "",
    [switch]$AllowInsecureHttpDashboard,
    [switch]$AutoConfigure,
    [string]$PsExecPath = "C:\Tools\PsExec\psexec.exe",
    [string]$CollectorSharePath = "",
    [string]$CollectorShareName = "o365audit",
    [string]$DomainComputersGroup = "",
    [string[]]$FallbackTargets = @(),
    [string]$DefaultOuFilter = "",
    [string]$DefaultSiteFilter = "",
    [string[]]$AuditAdminGroups = @(),
    [string[]]$AuditReaderGroups = @(),
    [string[]]$MigrationPlannerGroups = @(),
    [string]$GmsaAccount = "",
    [PSCredential]$ServiceCredential,
    [switch]$AllowLocalSystem,
    [switch]$AllowUnsignedPsExec,
    [switch]$EnableArtifactCopy,
    [string]$CopyTargetRoot = "",
    [string[]]$AllowedCopyTargetRoots = @(),
    [string[]]$AllowedCopySourceUncRoots = @(),
    [switch]$CopyVerifySha256,
    [switch]$DisableCopySha256,
    [switch]$SkipPublish,
    [switch]$FunctionsOnly
)

$ErrorActionPreference = 'Stop'
if ($CopyVerifySha256 -and $DisableCopySha256) {
    throw 'CopyVerifySha256 ve DisableCopySha256 birlikte kullanilamaz.'
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Bu script Administrator yetkisi ile calistirilmalidir."
    }
}

function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
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
            throw "Yonetilen deployment path'i reparse point iceremez: '$current'."
        }
    }
}

function Assert-NoReparsePointTree {
    param([Parameter(Mandatory)][string]$Root)

    Assert-NoReparsePointInPath -Path $Root
    $reparseItem = Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($null -ne $reparseItem) {
        throw "Deployment kaynak agaci reparse point iceremez: '$($reparseItem.FullName)'."
    }
}

function Assert-DirectoryCopyIntegrity {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$DestinationRoot
    )

    $normalizedSource = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\') + '\'
    foreach ($sourceFile in (Get-ChildItem -LiteralPath $SourceRoot -File -Force -Recurse)) {
        $relativePath = $sourceFile.FullName.Substring($normalizedSource.Length)
        $destinationFile = Join-Path $DestinationRoot $relativePath
        if (-not (Test-Path -LiteralPath $destinationFile -PathType Leaf)) {
            throw "Deployment copy dogrulamasi hedef dosyayi bulamadi: '$destinationFile'."
        }

        $sourceHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash
        if (-not $sourceHash.Equals($destinationHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Deployment copy SHA256 dogrulamasi basarisiz: '$relativePath'."
        }
    }
}

function Resolve-DashboardDnsName {
    param([string]$ExplicitName)

    $name = $ExplicitName.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($name)) {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($computerSystem.PartOfDomain -and -not [string]::IsNullOrWhiteSpace([string]$computerSystem.Domain)) {
                $name = "$env:COMPUTERNAME.$($computerSystem.Domain)"
            }
        }
        catch {}

        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = $env:COMPUTERNAME
        }
    }

    if ($name.Length -gt 253 -or $name -notmatch '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$') {
        throw "DashboardDnsName gecerli bir DNS hostname veya FQDN degil: '$name'."
    }

    return $name.ToLowerInvariant()
}

function Merge-WindowsAuthServerAllowlist {
    param(
        [string]$ExistingValue,
        [Parameter(Mandatory)][string]$ServerName
    )

    $values = @(
        @($ExistingValue -split ',')
        $ServerName
    ) |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique |
        Sort-Object
    return ($values -join ',')
}

function Set-LocalBrowserSsoPolicy {
    param([Parameter(Mandatory)][string]$ServerName)

    $edgePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    New-Item -Path $edgePolicyPath -Force | Out-Null
    $existingAllowlist = [string](Get-ItemProperty `
        -Path $edgePolicyPath `
        -Name 'AuthServerAllowlist' `
        -ErrorAction SilentlyContinue).AuthServerAllowlist
    $authServerAllowlist = Merge-WindowsAuthServerAllowlist `
        -ExistingValue $existingAllowlist `
        -ServerName $ServerName
    New-ItemProperty `
        -Path $edgePolicyPath `
        -Name 'AuthServerAllowlist' `
        -PropertyType String `
        -Value $authServerAllowlist `
        -Force | Out-Null

    $zoneMapPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey'
    New-Item -Path $zoneMapPath -Force | Out-Null
    New-ItemProperty `
        -Path $zoneMapPath `
        -Name "https://$ServerName" `
        -PropertyType String `
        -Value '1' `
        -Force | Out-Null

    Write-Host "Yerel Edge/Windows Integrated Authentication policy ayarlandi: $ServerName" -ForegroundColor DarkCyan
    Write-Warning 'Bu ayar yalnizca yonetim sunucusuna uygulanir. Diger domain istemcilerine ayni AuthServerAllowlist ve Local Intranet zone degerlerini GPO ile dagitin; credential delegation allowlist etkinlestirmeyin.'
}

function Test-CertificateDnsName {
    param(
        [Parameter(Mandatory)][string]$CertificateName,
        [Parameter(Mandatory)][string]$RequestedName
    )

    $certificateName = $CertificateName.Trim().TrimEnd('.').ToLowerInvariant()
    $requestedName = $RequestedName.Trim().TrimEnd('.').ToLowerInvariant()
    if ($certificateName.Equals($requestedName, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    if (-not $certificateName.StartsWith('*.')) {
        return $false
    }

    $suffix = $certificateName.Substring(1)
    if (-not $requestedName.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $prefix = $requestedName.Substring(0, $requestedName.Length - $suffix.Length)
    return $prefix.Length -gt 0 -and -not $prefix.Contains('.')
}

function Get-CertificateDnsNames {
    param([Parameter(Mandatory)]$Certificate)

    $names = @()
    if ($null -ne $Certificate.DnsNameList) {
        $names = @($Certificate.DnsNameList | ForEach-Object { [string]$_.Unicode })
    }
    if ($names.Count -eq 0) {
        $fallbackName = $Certificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::DnsName,
            $false)
        if (-not [string]::IsNullOrWhiteSpace($fallbackName)) {
            $names = @($fallbackName)
        }
    }

    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-TlsCertificateCandidate {
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$DnsName
    )

    if (-not $Certificate.HasPrivateKey) {
        return $false
    }
    if ($Certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        return $false
    }
    if ($Certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow) {
        return $false
    }

    $ekuExtension = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        Select-Object -First 1
    if ($null -eq $ekuExtension -or -not ($ekuExtension.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.1' })) {
        return $false
    }

    return [bool](Get-CertificateDnsNames -Certificate $Certificate |
        Where-Object { Test-CertificateDnsName -CertificateName $_ -RequestedName $DnsName } |
        Select-Object -First 1)
}

function New-AutomaticTlsCertificate {
    param([Parameter(Mandatory)][string]$DnsName)

    $dnsNames = @($DnsName, $env:COMPUTERNAME) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    $getCertificate = Get-Command Get-Certificate -ErrorAction SilentlyContinue
    if ($getCertificate) {
        try {
            Write-Host "AD CS Machine sertifika enrollment deneniyor: $DnsName" -ForegroundColor DarkCyan
            $enrollment = Get-Certificate `
                -Template 'Machine' `
                -DnsName $dnsNames `
                -CertStoreLocation 'Cert:\LocalMachine\My' `
                -ErrorAction Stop
            if (
                $null -ne $enrollment.Certificate -and
                (Test-TlsCertificateCandidate -Certificate $enrollment.Certificate -DnsName $DnsName)
            ) {
                return $enrollment.Certificate
            }

            Write-Warning 'AD CS enrollment bir sertifika dondurdu ancak sertifika TLS gereksinimlerini karsilamadi.'
        }
        catch {
            Write-Warning "AD CS Machine enrollment kullanilamadi: $($_.Exception.Message)"
        }
    }

    $newSelfSignedCertificate = Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue
    if (-not $newSelfSignedCertificate) {
        throw 'Otomatik TLS icin uygun sertifika bulunamadi ve New-SelfSignedCertificate kullanilamiyor.'
    }

    Write-Warning 'Kurumsal CA sertifikasi bulunamadi. HTTPS icin self-signed sertifika uretiliyor; istemci guveni GPO veya kurumsal PKI ile ayrica dagitilmalidir.'
    return New-SelfSignedCertificate `
        -Type SSLServerAuthentication `
        -Subject "CN=$DnsName" `
        -DnsName $dnsNames `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -FriendlyName 'O365AuditTool automatic TLS' `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddYears(2)
}

function Remove-DeploymentDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $leaf = Split-Path $resolvedPath -Leaf
    if (
        -not $resolvedPath.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch '^\.(?:staging|rollback|failed)-[0-9a-f]{32}$'
    ) {
        throw "Guvenli olmayan deployment cleanup path'i reddedildi: '$resolvedPath'."
    }

    Remove-Item -LiteralPath $resolvedPath -Recurse -Force
}

function Resolve-TlsCertificateThumbprint {
    param(
        [string]$Thumbprint,
        [bool]$AllowInsecure,
        [string]$DnsName,
        [bool]$AutoConfigure
    )

    if ($AllowInsecure) {
        Write-Warning 'Dashboard HTTP istisnasi etkin. Bu mod yalnizca izole test aginda kullanilmalidir.'
        return ''
    }
    if ([string]::IsNullOrWhiteSpace($Thumbprint) -and $AutoConfigure) {
        $certificate = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object { Test-TlsCertificateCandidate -Certificate $_ -DnsName $DnsName } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1
        if ($null -eq $certificate) {
            $certificate = New-AutomaticTlsCertificate -DnsName $DnsName
        }
        if ($null -eq $certificate -or [string]::IsNullOrWhiteSpace([string]$certificate.Thumbprint)) {
            throw "DashboardDnsName '$DnsName' icin otomatik TLS sertifikasi olusturulamadi."
        }

        $Thumbprint = [string]$certificate.Thumbprint
        Write-Host "TLS sertifikasi otomatik secildi: $Thumbprint" -ForegroundColor DarkCyan
    }
    elseif ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        throw 'Production dashboard icin -TlsCertificateThumbprint zorunludur. Otomatik secim icin -AutoConfigure, yalnizca izole test icin -AllowInsecureHttpDashboard kullanilabilir.'
    }

    $normalized = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{40,128}$') {
        throw 'TlsCertificateThumbprint gecerli hexadecimal sertifika thumbprint degerinde degil.'
    }

    $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$normalized" -ErrorAction SilentlyContinue
    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "LocalMachine\\My deposunda private key iceren TLS sertifikasi bulunamadi: '$normalized'."
    }
    if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        throw "TLS sertifikasinin suresi dolmus: '$normalized'."
    }
    if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow) {
        throw "TLS sertifikasi henuz gecerli degil: '$normalized'."
    }

    if (-not (Test-TlsCertificateCandidate -Certificate $certificate -DnsName $DnsName)) {
        $certificateDnsNames = @(Get-CertificateDnsNames -Certificate $certificate)
        throw "TLS sertifikasi private key, tarih, Server Authentication EKU veya DashboardDnsName '$DnsName' gereksinimini karsilamiyor. Sertifika adlari: $($certificateDnsNames -join ', ')."
    }

    return $normalized
}

function Ensure-HttpSpns {
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][string]$DnsName
    )

    $setSpnPath = Join-Path $env:SystemRoot 'System32\setspn.exe'
    if (-not (Test-Path -LiteralPath $setSpnPath -PathType Leaf)) {
        throw "setspn.exe bulunamadi; Kerberos HTTP SPN dogrulanamiyor."
    }

    $names = @($DnsName, $DnsName.Split('.')[0]) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    foreach ($name in $names) {
        $spn = "HTTP/$name"
        $existingForAccount = @(& $setSpnPath -L $AccountName 2>&1)
        if ($LASTEXITCODE -eq 0 -and ($existingForAccount | Where-Object { $_.Trim().Equals($spn, [StringComparison]::OrdinalIgnoreCase) })) {
            continue
        }

        $result = @(& $setSpnPath -S $spn $AccountName 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Kerberos SPN kaydedilemedi: setspn -S $spn $AccountName. Cikti: $($result -join ' '). Duplicate SPN veya AD yetkisini kontrol edin."
        }
    }
}

function Grant-TlsPrivateKeyRead {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$AccountSid
    )

    $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop
    $key = $null
    $keyPath = $null
    try {
        $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        if ($null -eq $key) {
            $key = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
        }

        if ($key -is [Security.Cryptography.RSACng] -or $key -is [Security.Cryptography.ECDsaCng]) {
            $keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$($key.Key.UniqueName)"
        }
        elseif ($key -is [Security.Cryptography.RSACryptoServiceProvider]) {
            $containerName = $key.CspKeyContainerInfo.UniqueKeyContainerName
            $keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$containerName"
        }

        if ([string]::IsNullOrWhiteSpace($keyPath) -or -not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
            throw "TLS private key dosyasi cozumlenemedi. Sertifikanin machine-key olarak import edildigini dogrulayin: '$Thumbprint'."
        }

        $keyAcl = Get-Acl -LiteralPath $keyPath
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $AccountSid,
            [Security.AccessControl.FileSystemRights]::Read,
            [Security.AccessControl.AccessControlType]::Allow)
        $keyAcl.SetAccessRule($rule)
        Set-Acl -LiteralPath $keyPath -AclObject $keyAcl
    }
    finally {
        if ($key -is [IDisposable]) {
            $key.Dispose()
        }
    }
}

function Ensure-TlsPrivateKeyAccess {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][hashtable]$Identity
    )

    if ($Identity.Type -eq 'LocalSystem') {
        if ($null -eq $Identity.AclSid -or $Identity.AclSid.Value -ne 'S-1-5-18') {
            throw 'LocalSystem servis kimligi beklenen S-1-5-18 SID degerine sahip degil.'
        }

        # Machine certificate keys grant SYSTEM access by default; provider-specific file ACL lookup is unnecessary.
        Write-Verbose "LocalSystem TLS private key erisimi machine-key varsayilan ACL'i ile saglanacak."
        return
    }

    Grant-TlsPrivateKeyRead -Thumbprint $Thumbprint -AccountSid $Identity.AclSid
}

function Resolve-DotNetPath {
    param([bool]$Publishing)

    $candidates = @()
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
        $candidates += $command.Source
    }

    $candidates += @(
        $(if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { Join-Path $env:USERPROFILE '.dotnet\dotnet.exe' }),
        (Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'),
        'C:\Program Files\dotnet\dotnet.exe'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }

        if ($Publishing) {
            $sdks = @(& $candidate --list-sdks 2>$null)
            if ($LASTEXITCODE -eq 0 -and ($sdks -match '^10\.\d+\.\d+')) {
                return $candidate
            }
        }
        else {
            $runtimes = @(& $candidate --list-runtimes 2>$null)
            if ($LASTEXITCODE -eq 0 -and ($runtimes -match '^Microsoft\.ASPNetCore\.App 10\.')) {
                return $candidate
            }
        }
    }

    $requirement = if ($Publishing) { '.NET 10 SDK' } else { 'ASP.NET Core Runtime 10' }
    throw "$requirement bulunamadi. PATH, %USERPROFILE%\.dotnet ve Program Files konumlari kontrol edildi."
}

function Assert-DotNet10 {
    param(
        [string]$DotNetPath,
        [bool]$Publishing
    )

    & $DotNetPath --info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet calistirilamadi: '$DotNetPath'."
    }

    if ($Publishing) {
        $sdks = @(& $DotNetPath --list-sdks 2>$null)
        if (-not ($sdks -match '^10\.\d+\.\d+')) {
            throw ".NET 10 SDK bulunamadi. Kaynak koddan publish icin Microsoft.DotNet.SDK.10 kurulmalidir."
        }
    }

    $runtimes = @(& $DotNetPath --list-runtimes 2>$null)
    if (-not ($runtimes -match '^Microsoft\.ASPNetCore\.App 10\.')) {
        throw "ASP.NET Core Runtime 10 bulunamadi. Framework-dependent servisi calistirmak icin gereklidir."
    }
}

function Assert-PsExec {
    param(
        [string]$Path,
        [bool]$AllowUnsigned
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "PsExec bulunamadi: '$Path'. Sysinternals PsExec'i bu konuma kopyalayin veya -PsExecPath belirtin."
    }

    if ([IO.Path]::GetExtension($Path) -ne '.exe') {
        throw "PsExecPath bir .exe dosyasi gostermelidir: '$Path'."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -and -not $AllowUnsigned) {
        throw "PsExec imzasi gecerli degil (durum: $($signature.Status)). Dogru Sysinternals binary'sini kullanin. Bilincli istisna icin -AllowUnsignedPsExec gerekir."
    }
    if (-not $AllowUnsigned -and $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') {
        throw "PsExec Microsoft Corporation tarafindan imzalanmamis. Resmi Sysinternals binary'sini kullanin."
    }
}

function Resolve-AccountNameBySid([string]$SidValue) {
    try {
        $sid = New-Object Security.Principal.SecurityIdentifier($SidValue)
        return $sid.Translate([Security.Principal.NTAccount]).Value
    }
    catch {
        throw "SID hesap adina cevrilemedi: '$SidValue'. $($_.Exception.Message)"
    }
}

function Resolve-AccountSid([string]$AccountName) {
    try {
        $account = New-Object Security.Principal.NTAccount($AccountName)
        return $account.Translate([Security.Principal.SecurityIdentifier])
    }
    catch {
        throw "Hesap SID'e cevrilemedi: '$AccountName'. Hesabin domain'de mevcut oldugunu ve sunucunun domain erisimi oldugunu dogrulayin."
    }
}

function Resolve-DomainGroupList {
    param(
        [string]$RoleName,
        [string[]]$GroupNames
    )

    $requestedGroups = @($GroupNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
    if ($requestedGroups.Count -eq 0) {
        throw "$RoleName icin en az bir AD grubu belirtilmelidir. Ornek: -${RoleName}Groups 'DOMAIN\GG_O365_$RoleName'."
    }

    $resolvedGroups = @()
    $getAdGroup = Get-Command Get-ADGroup -ErrorAction SilentlyContinue
    foreach ($groupName in $requestedGroups) {
        if ($groupName -notmatch '^[^\\]+\\[^\\]+$' -or $groupName.StartsWith('.\')) {
            throw "$RoleName grup adi 'DOMAIN\GrupAdi' biciminde olmalidir: '$groupName'."
        }

        $sid = Resolve-AccountSid -AccountName $groupName
        if ($getAdGroup) {
            try {
                Get-ADGroup -Identity $sid.Value -ErrorAction Stop | Out-Null
            }
            catch {
                throw "$RoleName eslemesi bir AD grubu olarak dogrulanamadi: '$groupName'. $($_.Exception.Message)"
            }
        }

        $resolvedGroups += $sid.Translate([Security.Principal.NTAccount]).Value
    }

    if (-not $getAdGroup) {
        Write-Warning "$RoleName hesaplari SID ile cozuldu ancak ActiveDirectory modulu olmadigi icin grup nesnesi olduklari dogrulanamadi."
    }

    return @($resolvedGroups | Select-Object -Unique)
}

function Resolve-FallbackTargets([string[]]$Targets) {
    $resolvedTargets = @($Targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
    foreach ($target in $resolvedTargets) {
        if ($target -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$') {
            throw "Fallback target gecerli bir hostname veya FQDN degil: '$target'."
        }
    }
    return $resolvedTargets
}

function Resolve-CopyRoot {
    param(
        [string]$Path,
        [string]$ParameterName,
        [switch]$AllowEmpty
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($AllowEmpty) {
            return ''
        }
        throw "$ParameterName bos olamaz."
    }

    $trimmedPath = $Path.Trim()
    if ($trimmedPath -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))') {
        throw "$ParameterName tam bir yerel veya UNC path olmalidir: '$trimmedPath'."
    }

    try {
        $resolvedPath = [IO.Path]::GetFullPath($trimmedPath).TrimEnd('\')
    }
    catch {
        throw "$ParameterName normalize edilemedi: '$trimmedPath'. $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        throw "$ParameterName gecersiz: '$trimmedPath'."
    }

    $localDriveRoot = [IO.Path]::GetPathRoot($resolvedPath).TrimEnd('\')
    if ($resolvedPath -match '^[A-Za-z]:$' -and $resolvedPath.Equals($localDriveRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$ParameterName bir surucu kok dizini olamaz: '$resolvedPath'. Ayrilmis bir alt dizin kullanin."
    }

    return $resolvedPath
}

function Test-PathWithinRoot {
    param(
        [string]$Path,
        [string]$Root
    )

    if ($Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    return $Path.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase)
}

function Remove-PublishedSampleMappings([string]$ApplicationDirectory) {
    $baseSettingsPath = Join-Path $ApplicationDirectory 'appsettings.json'
    if (-not (Test-Path -LiteralPath $baseSettingsPath -PathType Leaf)) {
        throw "Publish cikisinda appsettings.json bulunamadi: '$baseSettingsPath'."
    }

    $baseSettings = Get-Content -LiteralPath $baseSettingsPath -Raw | ConvertFrom-Json
    if ($null -ne $baseSettings.Collector) {
        $baseSettings.Collector.FallbackTargets = @()
    }
    if ($null -ne $baseSettings.Auth -and $null -ne $baseSettings.Auth.RoleMappings) {
        $baseSettings.Auth.RoleMappings.AuditAdmin = @()
        $baseSettings.Auth.RoleMappings.AuditReader = @()
        $baseSettings.Auth.RoleMappings.MigrationPlanner = @()
    }

    $baseSettings | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $baseSettingsPath -Encoding utf8
}

function Get-DefaultDomainNamingContext {
    try {
        $rootDse = New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $domainDn = [string]$rootDse.Properties['defaultNamingContext'].Value
        if ([string]::IsNullOrWhiteSpace($domainDn)) {
            throw "defaultNamingContext bos."
        }

        return $domainDn
    }
    catch {
        throw "AD defaultNamingContext cozulemedi. Sunucunun domain uyeligini ve LDAP erisimini kontrol edin. $($_.Exception.Message)"
    }
}

function Resolve-DomainRidAccount {
    param([Parameter(Mandatory)][ValidateRange(1, 999999999)][int]$Rid)

    try {
        $domainDn = Get-DefaultDomainNamingContext

        $domainEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$domainDn")
        $domainSidBytes = [byte[]]$domainEntry.Properties['objectSid'].Value
        $domainSid = New-Object Security.Principal.SecurityIdentifier($domainSidBytes, 0)
        $accountSid = New-Object Security.Principal.SecurityIdentifier("$($domainSid.Value)-$Rid")
        return @{
            Name = $accountSid.Translate([Security.Principal.NTAccount]).Value
            Sid = $accountSid
        }
    }
    catch {
        throw "Domain hesabi RID $Rid ile cozulemedi. Domain baglantisini kontrol edin. $($_.Exception.Message)"
    }
}

function Resolve-DomainComputersAccount {
    param([string]$ExplicitAccount)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitAccount)) {
        $sid = Resolve-AccountSid -AccountName $ExplicitAccount
        return @{
            Name = $sid.Translate([Security.Principal.NTAccount]).Value
            Sid = $sid
        }
    }

    try {
        return Resolve-DomainRidAccount -Rid 515
    }
    catch {
        throw "Domain Computers grubu RID 515 ile cozulemedi. Domain baglantisini kontrol edin veya -DomainComputersGroup 'DOMAIN\grup' belirtin. $($_.Exception.Message)"
    }
}

function Resolve-ServiceIdentity {
    $selectedCount = @(
        -not [string]::IsNullOrWhiteSpace($GmsaAccount)
        $null -ne $ServiceCredential
        $AllowLocalSystem.IsPresent
    ).Where({ $_ }).Count

    if ($selectedCount -ne 1) {
        throw "Tam olarak bir servis kimligi secilmelidir: -GmsaAccount, -ServiceCredential veya acik risk kabuluyla -AllowLocalSystem."
    }

    if (-not [string]::IsNullOrWhiteSpace($GmsaAccount)) {
        if ($GmsaAccount -notmatch '^[^\\]+\\[^\\]+\$$') {
            throw "GmsaAccount 'DOMAIN\hesap$' biciminde ve sonunda `$ olacak sekilde verilmelidir."
        }

        $sid = Resolve-AccountSid -AccountName $GmsaAccount
        $testCommand = Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue
        if ($testCommand) {
            $shortName = ($GmsaAccount.Split('\')[-1]).TrimEnd('$')
            if (-not (Test-ADServiceAccount -Identity $shortName)) {
                throw "gMSA bu sunucuda kullanilamiyor: '$GmsaAccount'. Install-ADServiceAccount ve PrincipalsAllowedToRetrieveManagedPassword ayarlarini kontrol edin."
            }
        }
        else {
            Write-Warning "ActiveDirectory modulu bulunamadigi icin Test-ADServiceAccount calistirilamadi. SCM servis baslatma asamasinda gMSA'yi dogrulayacak."
        }

        return @{
            Type = 'gMSA'
            ScAccount = $GmsaAccount
            SpnAccount = $GmsaAccount
            AclSid = $sid
            ShareAccount = $sid.Translate([Security.Principal.NTAccount]).Value
        }
    }

    if ($null -ne $ServiceCredential) {
        $userName = $ServiceCredential.UserName
        if ($userName -notmatch '^[^\\]+\\[^\\]+$' -or $userName.StartsWith('.\')) {
            throw "ServiceCredential bir domain hesabi olmali ve 'DOMAIN\kullanici' biciminde verilmelidir."
        }

        $sid = Resolve-AccountSid -AccountName $userName
        return @{
            Type = 'Credential'
            ScAccount = $userName
            SpnAccount = $userName
            AclSid = $sid
            ShareAccount = $sid.Translate([Security.Principal.NTAccount]).Value
        }
    }

    $localSystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    Write-Warning "LocalSystem acik olarak secildi. Uzak cihaz erisimi yonetim sunucusunun bilgisayar hesabi ile yapilir; gMSA onerilir."
    return @{
        Type = 'LocalSystem'
        ScAccount = 'LocalSystem'
        SpnAccount = "$env:USERDOMAIN\$env:COMPUTERNAME`$"
        AclSid = $localSystemSid
        ShareAccount = $null
    }
}

function New-ManagedDirectoryAcl {
    param(
        [Security.Principal.SecurityIdentifier]$AdministratorsSid,
        [Security.Principal.SecurityIdentifier]$SystemSid,
        [Security.Principal.SecurityIdentifier]$ServiceSid,
        [string]$ServiceRights,
        [Security.Principal.SecurityIdentifier]$AdditionalReadSid
    )

    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow

    $null = $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SystemSid, 'FullControl', $inheritance, $none, $allow)))
    $null = $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdministratorsSid, 'FullControl', $inheritance, $none, $allow)))
    $null = $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ServiceSid, $ServiceRights, $inheritance, $none, $allow)))
    if ($null -ne $AdditionalReadSid -and $AdditionalReadSid.Value -ne $ServiceSid.Value) {
        $null = $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdditionalReadSid, 'ReadAndExecute', $inheritance, $none, $allow)))
    }

    return $acl
}

function Set-ManagedDirectoryAcl {
    param(
        [string]$Path,
        [Security.Principal.SecurityIdentifier]$AdministratorsSid,
        [Security.Principal.SecurityIdentifier]$SystemSid,
        [Security.Principal.SecurityIdentifier]$ServiceSid,
        [string]$ServiceRights,
        [Security.Principal.SecurityIdentifier]$AdditionalReadSid
    )

    $acl = New-ManagedDirectoryAcl `
        -AdministratorsSid $AdministratorsSid `
        -SystemSid $SystemSid `
        -ServiceSid $ServiceSid `
        -ServiceRights $ServiceRights `
        -AdditionalReadSid $AdditionalReadSid
    Set-DirectoryAcl -Path $Path -Acl $acl
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

function Initialize-ManagedDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$AdministratorsSid,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$SystemSid,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ServiceSid,
        [Parameter(Mandatory)][string]$ServiceRights,
        [Security.Principal.SecurityIdentifier]$AdditionalReadSid
    )

    $parent = Split-Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Assert-NoReparsePointInPath -Path $parent
    }
    $acl = New-ManagedDirectoryAcl `
        -AdministratorsSid $AdministratorsSid `
        -SystemSid $SystemSid `
        -ServiceSid $ServiceSid `
        -ServiceRights $ServiceRights `
        -AdditionalReadSid $AdditionalReadSid
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

function Ensure-CollectorShare {
    param(
        [string]$Name,
        [string]$Path,
        [string]$AdministratorsAccount,
        [string[]]$ReadAccounts
    )

    $existingShare = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if ($existingShare) {
        $existingPath = [IO.Path]::GetFullPath($existingShare.Path).TrimEnd('\')
        $requestedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        if (-not $existingPath.Equals($requestedPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "SMB share '$Name' zaten farkli bir path kullaniyor: '$existingPath'. Guvenlik nedeniyle otomatik degistirilmedi."
        }
    }
    else {
        New-SmbShare -Name $Name -Path $Path -FullAccess $AdministratorsAccount -ReadAccess $ReadAccounts -FolderEnumerationMode AccessBased | Out-Null
    }

    Grant-SmbShareAccess -Name $Name -AccountName $AdministratorsAccount -AccessRight Full -Force | Out-Null
    foreach ($account in $ReadAccounts | Select-Object -Unique) {
        Grant-SmbShareAccess -Name $Name -AccountName $account -AccessRight Read -Force | Out-Null
    }

    foreach ($sidValue in @('S-1-1-0', 'S-1-5-32-546')) {
        try {
            $unsafeAccount = Resolve-AccountNameBySid -SidValue $sidValue
            Revoke-SmbShareAccess -Name $Name -AccountName $unsafeAccount -Force -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Verbose "SMB ACE temizleme atlandi: $sidValue"
        }
    }
}

function Invoke-ServiceControl([string[]]$Arguments) {
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $safeArguments = @($Arguments)
        $passwordIndex = [Array]::IndexOf($safeArguments, 'password=')
        if ($passwordIndex -ge 0 -and ($passwordIndex + 1) -lt $safeArguments.Count) {
            $safeArguments[$passwordIndex + 1] = '<redacted>'
        }
        throw "sc.exe basarisiz oldu: sc.exe $($safeArguments -join ' '). Cikti: $($output -join ' ')"
    }
}

function Configure-Service {
    param(
        [string]$Name,
        [string]$BinPath,
        [hashtable]$Identity
    )

    $existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($Identity.Type -eq 'Credential') {
        if ($existing) {
            $escapedName = $Name.Replace("'", "''")
            $cimService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'"
            if ($null -eq $cimService) {
                throw "Mevcut servis CIM uzerinden bulunamadi: '$Name'."
            }

            $passwordPointer = [IntPtr]::Zero
            $plainPassword = $null
            try {
                $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceCredential.Password)
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
                $changeResult = Invoke-CimMethod -InputObject $cimService -MethodName Change -Arguments @{
                    DisplayName = $Name
                    PathName = $BinPath
                    StartMode = 'Automatic'
                    StartName = $Identity.ScAccount
                    StartPassword = $plainPassword
                }
                if ($changeResult.ReturnValue -ne 0) {
                    throw "Win32_Service.Change hata kodu dondurdu: $($changeResult.ReturnValue)."
                }
            }
            finally {
                $plainPassword = $null
                if ($passwordPointer -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
                }
            }
        }
        else {
            New-Service -Name $Name -BinaryPathName $BinPath -DisplayName $Name -StartupType Automatic -Credential $ServiceCredential | Out-Null
        }

        Invoke-ServiceControl -Arguments @('config', $Name, 'start=', 'delayed-auto', 'binPath=', $BinPath, 'DisplayName=', $Name)
    }
    else {
        $operation = if ($existing) { 'config' } else { 'create' }
        Invoke-ServiceControl -Arguments @(
            $operation,
            $Name,
            'binPath=', $BinPath,
            'start=', 'delayed-auto',
            'DisplayName=', $Name,
            'obj=', $Identity.ScAccount
        )
    }

    Invoke-ServiceControl -Arguments @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000')
    Invoke-ServiceControl -Arguments @('failureflag', $Name, '1')
    Invoke-ServiceControl -Arguments @('description', $Name, 'O365 PST migration inventory and audit service')
}

if ($FunctionsOnly) { return }

Assert-Admin

$repoRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    ''
}
else {
    Split-Path $PSScriptRoot -Parent
}

$usingPublishedBundle = -not [string]::IsNullOrWhiteSpace($PublishedAppPath)
if ($usingPublishedBundle) {
    $PublishedAppPath = [IO.Path]::GetFullPath($PublishedAppPath)
    if (-not (Test-Path -LiteralPath $PublishedAppPath -PathType Container)) {
        throw "PublishedAppPath gecersiz veya erisilemiyor: '$PublishedAppPath'."
    }

    $publishedExe = Join-Path $PublishedAppPath 'O365AuditTool.exe'
    $publishedDll = Join-Path $PublishedAppPath 'O365AuditTool.dll'
    if (
        -not (Test-Path -LiteralPath $publishedExe -PathType Leaf) -and
        -not (Test-Path -LiteralPath $publishedDll -PathType Leaf)
    ) {
        throw "PublishedAppPath uygulama binary'si icermiyor: '$PublishedAppPath'."
    }
    Assert-NoReparsePointInPath -Path $PublishedAppPath
}
else {
    if (-not $SkipPublish) {
        if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
            if ([string]::IsNullOrWhiteSpace($repoRoot)) {
                throw "ProjectPath zorunludur. Bootstrap kurulumunda PublishedAppPath kullanin."
            }
            $ProjectPath = Join-Path $repoRoot 'src\O365AuditTool'
        }

        $ProjectPath = [IO.Path]::GetFullPath($ProjectPath)
        $csprojPath = Join-Path $ProjectPath 'O365AuditTool.csproj'
        if (-not (Test-Path -LiteralPath $csprojPath -PathType Leaf)) {
            throw "ProjectPath gecersiz: '$ProjectPath'. O365AuditTool.csproj bulunamadi."
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($CollectorPath)) {
    $CollectorPath = [IO.Path]::GetFullPath($CollectorPath)
    if (-not (Test-Path -LiteralPath $CollectorPath -PathType Leaf)) {
        throw "CollectorPath gecersiz veya erisilemiyor: '$CollectorPath'."
    }
    Assert-NoReparsePointInPath -Path $CollectorPath
}

$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
if ([string]::IsNullOrWhiteSpace($CollectorSharePath)) {
    $CollectorSharePath = Join-Path $InstallRoot 'share'
}
$CollectorSharePath = [IO.Path]::GetFullPath($CollectorSharePath)
if ($Port -eq $HealthPort) {
    throw 'Port ve HealthPort farkli olmalidir.'
}
if ([IO.Path]::GetPathRoot($InstallRoot).TrimEnd('\') -eq $InstallRoot.TrimEnd('\')) {
    throw "InstallRoot bir surucu kok dizini olamaz: '$InstallRoot'."
}
if (-not (Test-PathWithinRoot -Path $CollectorSharePath.TrimEnd('\') -Root $InstallRoot.TrimEnd('\'))) {
    throw "CollectorSharePath InstallRoot altinda olmalidir; yonetilmeyen dizinlerin ACL'leri degistirilmez: '$CollectorSharePath'."
}
if ($CollectorShareName -notmatch '^[A-Za-z0-9_-]+$') {
    throw "CollectorShareName yalnizca harf, rakam, alt cizgi ve tire icerebilir."
}
if ($ServiceName -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "ServiceName yalnizca harf, rakam, nokta, alt cizgi ve tire icerebilir."
}

$dotnet = $null
if (-not $usingPublishedBundle -and -not $SkipPublish) {
    $dotnet = Resolve-DotNetPath -Publishing $true
    Assert-DotNet10 -DotNetPath $dotnet -Publishing $true
}
Assert-PsExec -Path $PsExecPath -AllowUnsigned $AllowUnsignedPsExec.IsPresent

if ($AutoConfigure) {
    $selectedIdentityCount = @(
        -not [string]::IsNullOrWhiteSpace($GmsaAccount)
        $null -ne $ServiceCredential
        $AllowLocalSystem.IsPresent
    ).Where({ $_ }).Count
    if ($selectedIdentityCount -eq 0) {
        $AllowLocalSystem = $true
        Write-Warning 'AutoConfigure servis kimligi verilmedigi icin LocalSystem sececek. Endpoint uzak yonetim yetkisi yonetim sunucusunun bilgisayar hesabina verilmelidir.'
    }

    if (
        @($AuditAdminGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0 -or
        @($AuditReaderGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0 -or
        @($MigrationPlannerGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0
    ) {
        $domainAdmins = Resolve-DomainRidAccount -Rid 512
        if (@($AuditAdminGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
            $AuditAdminGroups = @($domainAdmins.Name)
        }
        if (@($AuditReaderGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
            $AuditReaderGroups = @($domainAdmins.Name)
        }
        if (@($MigrationPlannerGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
            $MigrationPlannerGroups = @($domainAdmins.Name)
        }
        Write-Warning "AutoConfigure eksik RBAC rollerini '$($domainAdmins.Name)' grubuna bagladi. Kurulum sonrasi ayrik least-privilege gruplarla degistirin."
    }

    if ([string]::IsNullOrWhiteSpace($DefaultOuFilter) -and [string]::IsNullOrWhiteSpace($DefaultSiteFilter)) {
        $DefaultOuFilter = Get-DefaultDomainNamingContext
        Write-Warning "AutoConfigure tarama kapsaminda domain kokunu kullanacak: '$DefaultOuFilter'. Buyuk domainlerde OU/site ile daraltin."
    }
}

$serviceIdentity = Resolve-ServiceIdentity
$resolvedDashboardDnsName = Resolve-DashboardDnsName -ExplicitName $DashboardDnsName
if ($AutoConfigure) {
    try {
        Set-LocalBrowserSsoPolicy -ServerName $resolvedDashboardDnsName
    }
    catch {
        Write-Warning "Yerel browser SSO policy ayarlanamadi; deployment devam edecek. GPO ile AuthServerAllowlist ve Local Intranet zone ayarlayin. $($_.Exception.Message)"
    }
}
$resolvedTlsCertificateThumbprint = Resolve-TlsCertificateThumbprint `
    -Thumbprint $TlsCertificateThumbprint `
    -AllowInsecure $AllowInsecureHttpDashboard.IsPresent `
    -DnsName $resolvedDashboardDnsName `
    -AutoConfigure $AutoConfigure.IsPresent
if (-not $AllowInsecureHttpDashboard) {
    Ensure-HttpSpns -AccountName $serviceIdentity.SpnAccount -DnsName $resolvedDashboardDnsName
    Ensure-TlsPrivateKeyAccess `
        -Thumbprint $resolvedTlsCertificateThumbprint `
        -Identity $serviceIdentity
}
$resolvedAuditAdminGroups = @(Resolve-DomainGroupList -RoleName 'AuditAdmin' -GroupNames $AuditAdminGroups)
$resolvedAuditReaderGroups = @(Resolve-DomainGroupList -RoleName 'AuditReader' -GroupNames $AuditReaderGroups)
$resolvedMigrationPlannerGroups = @(Resolve-DomainGroupList -RoleName 'MigrationPlanner' -GroupNames $MigrationPlannerGroups)
$resolvedFallbackTargets = @(Resolve-FallbackTargets -Targets $FallbackTargets)
$resolvedCopyTargetRoot = Resolve-CopyRoot -Path $CopyTargetRoot -ParameterName 'CopyTargetRoot' -AllowEmpty
$resolvedAllowedCopyTargetRoots = @(
    $AllowedCopyTargetRoots |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { Resolve-CopyRoot -Path $_ -ParameterName 'AllowedCopyTargetRoots' } |
        Select-Object -Unique
)
$resolvedAllowedCopySourceUncRoots = @(
    @(
        foreach ($sourceRoot in ($AllowedCopySourceUncRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            $resolvedSourceRoot = Resolve-CopyRoot -Path $sourceRoot -ParameterName 'AllowedCopySourceUncRoots'
            if ($resolvedSourceRoot -notlike '\\*') {
                throw "AllowedCopySourceUncRoots yalnizca UNC kokleri kabul eder: '$resolvedSourceRoot'."
            }
            $resolvedSourceRoot
        }
    ) | Select-Object -Unique
)

if ($EnableArtifactCopy) {
    if ([string]::IsNullOrWhiteSpace($resolvedCopyTargetRoot)) {
        throw "Artifact copy etkinlestirilemez: -CopyTargetRoot zorunludur."
    }
    if ($resolvedAllowedCopyTargetRoots.Count -eq 0) {
        throw "Artifact copy etkinlestirilemez: -AllowedCopyTargetRoots en az bir guvenli kok icermelidir."
    }
    if (-not ($resolvedAllowedCopyTargetRoots | Where-Object { Test-PathWithinRoot -Path $resolvedCopyTargetRoot -Root $_ })) {
        throw "CopyTargetRoot izin verilen koklerden birinin altinda degil: '$resolvedCopyTargetRoot'."
    }
    if (-not (Test-Path -LiteralPath $resolvedCopyTargetRoot -PathType Container)) {
        throw "CopyTargetRoot mevcut degil veya deployment hesabi tarafindan erisilemiyor: '$resolvedCopyTargetRoot'. Hedef dizini ve SMB/NTFS izinlerini once hazirlayin."
    }

    Write-Warning "Artifact copy etkin. Servis kimligi '$($serviceIdentity.ScAccount)' tum kaynak cihazlarda ADMIN$ okuma ve hedef '$resolvedCopyTargetRoot' uzerinde dosya olusturma/yazma yetkisine sahip olmalidir. Deployment hesabi ile yapilan path kontrolu servis kimliginin etkin yetkilerini dogrulamaz."
    if ($serviceIdentity.Type -eq 'LocalSystem') {
        Write-Warning "LocalSystem ile copy erisimi '$env:USERDOMAIN\$env:COMPUTERNAME`$' bilgisayar hesabi uzerinden yapilir. Kaynak ADMIN$ ve hedef share izinlerini bu hesap icin acmak yerine sinirli bir gMSA kullanilmasi onerilir."
    }
}

$domainComputers = Resolve-DomainComputersAccount -ExplicitAccount $DomainComputersGroup
$administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$administratorsName = $administratorsSid.Translate([Security.Principal.NTAccount]).Value
$systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')

$liveAppDir = Join-Path $InstallRoot 'app'
$deploymentId = [Guid]::NewGuid().ToString('N')
$stagingAppDir = Join-Path $InstallRoot ".staging-$deploymentId"
$rollbackAppDir = Join-Path $InstallRoot ".rollback-$deploymentId"
$failedAppDir = Join-Path $InstallRoot ".failed-$deploymentId"
$appDir = $stagingAppDir
$appDataDir = Join-Path $appDir 'data'
$dataDir = Join-Path $InstallRoot 'data'
$logDir = Join-Path $InstallRoot 'logs'

Assert-NoReparsePointInPath -Path (Split-Path $InstallRoot -Parent)
Initialize-ManagedDirectory -Path $InstallRoot -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute'
Initialize-ManagedDirectory -Path $stagingAppDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute'
Initialize-ManagedDirectory -Path $appDataDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
Initialize-ManagedDirectory -Path $dataDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
Initialize-ManagedDirectory -Path $logDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
Initialize-ManagedDirectory -Path $CollectorSharePath -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute' -AdditionalReadSid $domainComputers.Sid

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$restartOnFailure = $existingService -and $existingService.Status -eq 'Running'
$deploymentSwapped = $false

try {
    if ($usingPublishedBundle) {
        Assert-NoReparsePointTree -Root $PublishedAppPath
        foreach ($publishedItem in (Get-ChildItem -LiteralPath $PublishedAppPath -Force)) {
            Copy-Item -LiteralPath $publishedItem.FullName -Destination $appDir -Recurse -Force
        }
        Assert-DirectoryCopyIntegrity -SourceRoot $PublishedAppPath -DestinationRoot $appDir
    }
    elseif ($SkipPublish) {
        if (-not (Test-Path -LiteralPath $liveAppDir -PathType Container)) {
            throw "SkipPublish yalnizca mevcut bir deployment'i yeniden yapilandirabilir; live app dizini bulunamadi: '$liveAppDir'."
        }
        foreach ($liveItem in (Get-ChildItem -LiteralPath $liveAppDir -Force)) {
            Copy-Item -LiteralPath $liveItem.FullName -Destination $appDir -Recurse -Force
        }
    }
    else {
        Push-Location $ProjectPath
        try {
            & $dotnet publish -c Release -o $appDir
            if ($LASTEXITCODE -ne 0) {
                throw "dotnet publish hata kodu ile tamamlandi: $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }

    $applicationExe = Join-Path $appDir 'O365AuditTool.exe'
    $applicationDll = Join-Path $appDir 'O365AuditTool.dll'
    if (
        -not (Test-Path -LiteralPath $applicationExe -PathType Leaf) -and
        -not (Test-Path -LiteralPath $applicationDll -PathType Leaf)
    ) {
        throw "Uygulama binary'si bulunamadi: '$appDir'. -SkipPublish yalnizca hazir publish cikisi varsa kullanilabilir."
    }
    Remove-PublishedSampleMappings -ApplicationDirectory $appDir

    $collectorSource = $CollectorPath
    if ([string]::IsNullOrWhiteSpace($collectorSource) -and -not [string]::IsNullOrWhiteSpace($repoRoot)) {
        $collectorSource = Join-Path $repoRoot 'scripts\collector.ps1'
    }
    if (
        [string]::IsNullOrWhiteSpace($collectorSource) -or
        -not (Test-Path -LiteralPath $collectorSource -PathType Leaf)
    ) {
        if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            throw "collector.ps1 bulunamadi. Bundle kurulumunda CollectorPath zorunludur."
        }
        $collectorSource = Join-Path $PSScriptRoot 'collector.ps1'
    }
    if (-not (Test-Path -LiteralPath $collectorSource -PathType Leaf)) {
        throw "collector.ps1 bulunamadi. Beklenen konum: '$repoRoot\scripts\collector.ps1'."
    }

    $collectorDestination = Join-Path $CollectorSharePath 'collector.ps1'
    Copy-Item -LiteralPath $collectorSource -Destination $collectorDestination -Force
    $collectorSourceHash = (Get-FileHash -LiteralPath $collectorSource -Algorithm SHA256).Hash
    $collectorDestinationHash = (Get-FileHash -LiteralPath $collectorDestination -Algorithm SHA256).Hash
    if (-not $collectorSourceHash.Equals($collectorDestinationHash, [StringComparison]::OrdinalIgnoreCase)) {
        throw "collector.ps1 copy SHA256 dogrulamasi basarisiz."
    }

    $diagnosticsSource = Join-Path $PSScriptRoot 'Get-O365AuditDiagnostics.ps1'
    if (Test-Path -LiteralPath $diagnosticsSource -PathType Leaf) {
        Copy-Item -LiteralPath $diagnosticsSource `
            -Destination (Join-Path $InstallRoot 'Get-O365AuditDiagnostics.ps1') `
            -Force
    }

    $shareReaders = @($domainComputers.Name)
    if (-not [string]::IsNullOrWhiteSpace($serviceIdentity.ShareAccount)) {
        $shareReaders += $serviceIdentity.ShareAccount
    }
    Ensure-CollectorShare -Name $CollectorShareName -Path $CollectorSharePath -AdministratorsAccount $administratorsName -ReadAccounts $shareReaders

    $productionSettings = @{
        ConnectionStrings = @{ AuditDb = "Data Source=$dataDir\audit.db" }
        Server = @{
            HttpsPort = $Port
            HealthPort = $HealthPort
            PublicDnsName = $resolvedDashboardDnsName
            TlsCertificateThumbprint = $resolvedTlsCertificateThumbprint
            AllowInsecureHttp = $AllowInsecureHttpDashboard.IsPresent
        }
        Auth = @{
            RoleMappings = @{
                AuditAdmin = $resolvedAuditAdminGroups
                AuditReader = $resolvedAuditReaderGroups
                MigrationPlanner = $resolvedMigrationPlannerGroups
            }
        }
        Collector = @{
            PsExecPath = $PsExecPath
            RemoteScriptPath = "\\$env:COMPUTERNAME\$CollectorShareName\collector.ps1"
            DeviceTimeoutSeconds = 300
            MaxDeviceParallelism = 4
            JobPollingSeconds = 10
            DailyRunHour = 2
            DailyRunMinute = 15
            RetryMinutes = @(30, 120, 1440)
            ExcludeComputersInactiveDays = 120
            FallbackTargets = $resolvedFallbackTargets
            DefaultOuFilter = $DefaultOuFilter.Trim()
            DefaultSiteFilter = $DefaultSiteFilter.Trim()
        }
        Copy = @{
            Enabled = $EnableArtifactCopy.IsPresent
            DefaultTargetRoot = $resolvedCopyTargetRoot
            AllowedTargetRoots = $resolvedAllowedCopyTargetRoots
            AllowedSourceUncRoots = $resolvedAllowedCopySourceUncRoots
            MaxParallelism = 2
            BufferSizeMb = 4
            VerifySha256 = -not $DisableCopySha256.IsPresent
            MaxAttempts = 2
            PollingSeconds = 5
        }
        Retention = @{
            InventoryDays = 180
            CopyJobDays = 365
            InitialDelayMinutes = 5
        }
        Diagnostics = @{
            LogDirectory = $logDir
        }
    }
    $settingsPath = Join-Path $appDir 'appsettings.Production.json'
    $productionSettings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $settingsPath -Encoding utf8

    Assert-NoReparsePointInPath -Path $InstallRoot
    Set-ManagedDirectoryAcl -Path $InstallRoot -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute'
    Set-ManagedDirectoryAcl -Path $appDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute'
    Set-ManagedDirectoryAcl -Path $appDataDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
    Set-ManagedDirectoryAcl -Path $dataDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
    Set-ManagedDirectoryAcl -Path $logDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
    Set-ManagedDirectoryAcl -Path $CollectorSharePath -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute' -AdditionalReadSid $domainComputers.Sid

    if ($existingService -and $existingService.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    if (Test-Path -LiteralPath $liveAppDir -PathType Container) {
        Move-Item -LiteralPath $liveAppDir -Destination $rollbackAppDir
    }
    Move-Item -LiteralPath $stagingAppDir -Destination $liveAppDir
    $deploymentSwapped = $true
    $appDir = $liveAppDir
    $applicationExe = Join-Path $appDir 'O365AuditTool.exe'
    $applicationDll = Join-Path $appDir 'O365AuditTool.dll'

    $firewallRuleName = "O365AuditTool-$Port"
    Get-NetFirewallRule -DisplayName 'O365AuditTool-*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName -ne $firewallRuleName |
        Disable-NetFirewallRule | Out-Null
    $firewallRule = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
    if ($firewallRule) {
        $firewallRule | Set-NetFirewallRule -Enabled True -Action Allow -Profile Domain | Out-Null
        $firewallRule | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol TCP -LocalPort $Port | Out-Null
    }
    else {
        New-NetFirewallRule -DisplayName $firewallRuleName -Direction Inbound -Action Allow -Profile Domain -Protocol TCP -LocalPort $Port | Out-Null
    }

    $binaryPath = if (Test-Path -LiteralPath $applicationExe -PathType Leaf) {
        "`"$applicationExe`" --environment Production"
    }
    else {
        if ([string]::IsNullOrWhiteSpace($dotnet)) {
            $dotnet = Resolve-DotNetPath -Publishing $false
            Assert-DotNet10 -DotNetPath $dotnet -Publishing $false
        }
        "`"$dotnet`" `"$applicationDll`" --environment Production"
    }
    Configure-Service -Name $ServiceName -BinPath $binaryPath -Identity $serviceIdentity

    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

    $healthUri = "http://127.0.0.1:$HealthPort/health"
    $healthVerified = $false
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            $healthResponse = Invoke-WebRequest -Uri $healthUri -UseBasicParsing -TimeoutSec 5
            if ($healthResponse.StatusCode -eq 200) {
                $healthVerified = $true
                break
            }
        }
        catch {
            Write-Verbose "Health check denemesi $attempt basarisiz: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 2
    }

    if (-not $healthVerified) {
        throw "Servis basladi ancak health endpoint dogrulanamadi: '$healthUri'. Event Viewer ve servis loglarini kontrol edin."
    }

    Remove-DeploymentDirectory -Path $rollbackAppDir -Root $InstallRoot
}
catch {
    try {
        $failedService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($failedService -and $failedService.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            $failedService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        }

        if ($deploymentSwapped -and (Test-Path -LiteralPath $liveAppDir -PathType Container)) {
            Move-Item -LiteralPath $liveAppDir -Destination $failedAppDir
        }
        if (Test-Path -LiteralPath $rollbackAppDir -PathType Container) {
            Move-Item -LiteralPath $rollbackAppDir -Destination $liveAppDir
        }

        if ($restartOnFailure -and (Test-Path -LiteralPath $liveAppDir -PathType Container)) {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Rollback tamamlanamadi. '$rollbackAppDir' ve '$failedAppDir' dizinlerini, Event Viewer'i ve servis kimligini kontrol edin."
    }
    throw
}

Write-Host "Deployment tamamlandi." -ForegroundColor Green
$dashboardScheme = if ($AllowInsecureHttpDashboard) { 'http' } else { 'https' }
Write-Host "Dashboard: $dashboardScheme`://$resolvedDashboardDnsName`:$Port" -ForegroundColor Cyan
Write-Host "Collector share: \\$env:COMPUTERNAME\$CollectorShareName\collector.ps1" -ForegroundColor Cyan
Write-Host "Service: $ServiceName ($($serviceIdentity.Type): $($serviceIdentity.ScAccount))" -ForegroundColor Cyan
if ($EnableArtifactCopy) {
    Write-Host "Artifact copy: ENABLED -> $resolvedCopyTargetRoot (SHA256: $(-not $DisableCopySha256.IsPresent))" -ForegroundColor Yellow
}
else {
    Write-Host "Artifact copy: disabled (opt-in icin -EnableArtifactCopy gerekir)" -ForegroundColor DarkYellow
}
