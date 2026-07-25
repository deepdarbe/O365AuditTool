[CmdletBinding()]
param(
    [string]$ProjectPath = "",
    [string]$PublishedAppPath = "",
    [string]$CollectorPath = "",
    [string]$InstallRoot = "C:\temp\o365audit",
    [string]$ServiceName = "O365AuditTool",
    [ValidateRange(1, 65535)]
    [int]$Port = 5080,
    [string]$PsExecPath = "C:\Tools\PsExec\psexec.exe",
    [string]$CollectorSharePath = "C:\temp\o365audit\share",
    [string]$CollectorShareName = "o365audit",
    [string]$DomainComputersGroup = "",
    [string[]]$FallbackTargets = @(),
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
    [switch]$CopyVerifySha256,
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'

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

function Resolve-DotNetPath {
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'),
        'C:\Program Files\dotnet\dotnet.exe'
    ) | Select-Object -Unique

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw "dotnet bulunamadi. Bu uygulama icin .NET 8 SDK veya ASP.NET Core Runtime 8 gerekir."
}

function Assert-DotNet8 {
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
        if (-not ($sdks -match '^8\.\d+\.\d+')) {
            throw ".NET 8 SDK bulunamadi. Kaynak koddan publish icin Microsoft.DotNet.SDK.8 kurulmalidir."
        }
    }

    $runtimes = @(& $DotNetPath --list-runtimes 2>$null)
    if (-not ($runtimes -match '^Microsoft\.ASPNetCore\.App 8\.')) {
        throw "ASP.NET Core Runtime 8 bulunamadi. Framework-dependent servisi calistirmak icin gereklidir."
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
        $rootDse = New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $domainDn = [string]$rootDse.Properties['defaultNamingContext'].Value
        if ([string]::IsNullOrWhiteSpace($domainDn)) {
            throw "defaultNamingContext bos."
        }

        $domainEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$domainDn")
        $domainSidBytes = [byte[]]$domainEntry.Properties['objectSid'].Value
        $domainSid = New-Object Security.Principal.SecurityIdentifier($domainSidBytes, 0)
        $domainComputersSid = New-Object Security.Principal.SecurityIdentifier("$($domainSid.Value)-515")
        return @{
            Name = $domainComputersSid.Translate([Security.Principal.NTAccount]).Value
            Sid = $domainComputersSid
        }
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
            AclSid = $sid
            ShareAccount = $sid.Translate([Security.Principal.NTAccount]).Value
        }
    }

    $localSystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    Write-Warning "LocalSystem acik olarak secildi. Uzak cihaz erisimi yonetim sunucusunun bilgisayar hesabi ile yapilir; gMSA onerilir."
    return @{
        Type = 'LocalSystem'
        ScAccount = 'LocalSystem'
        AclSid = $localSystemSid
        ShareAccount = $null
    }
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

    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow

    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SystemSid, 'FullControl', $inheritance, $none, $allow)))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdministratorsSid, 'FullControl', $inheritance, $none, $allow)))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ServiceSid, $ServiceRights, $inheritance, $none, $allow)))
    if ($null -ne $AdditionalReadSid -and $AdditionalReadSid.Value -ne $ServiceSid.Value) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdditionalReadSid, 'ReadAndExecute', $inheritance, $none, $allow)))
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
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
}
else {
    if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
        if ([string]::IsNullOrWhiteSpace($repoRoot)) {
            throw "ProjectPath zorunludur. IEX/bootstrap kurulumunda PublishedAppPath kullanin."
        }
        $ProjectPath = Join-Path $repoRoot 'src\O365AuditTool'
    }

    $ProjectPath = [IO.Path]::GetFullPath($ProjectPath)
    $csprojPath = Join-Path $ProjectPath 'O365AuditTool.csproj'
    if (-not (Test-Path -LiteralPath $csprojPath -PathType Leaf)) {
        throw "ProjectPath gecersiz: '$ProjectPath'. O365AuditTool.csproj bulunamadi."
    }
}

if (-not [string]::IsNullOrWhiteSpace($CollectorPath)) {
    $CollectorPath = [IO.Path]::GetFullPath($CollectorPath)
    if (-not (Test-Path -LiteralPath $CollectorPath -PathType Leaf)) {
        throw "CollectorPath gecersiz veya erisilemiyor: '$CollectorPath'."
    }
}

$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$CollectorSharePath = [IO.Path]::GetFullPath($CollectorSharePath)
if ([IO.Path]::GetPathRoot($InstallRoot).TrimEnd('\') -eq $InstallRoot.TrimEnd('\')) {
    throw "InstallRoot bir surucu kok dizini olamaz: '$InstallRoot'."
}
if ($CollectorShareName -notmatch '^[A-Za-z0-9_-]+$') {
    throw "CollectorShareName yalnizca harf, rakam, alt cizgi ve tire icerebilir."
}
if ($ServiceName -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "ServiceName yalnizca harf, rakam, nokta, alt cizgi ve tire icerebilir."
}

$dotnet = $null
if (-not $usingPublishedBundle) {
    $dotnet = Resolve-DotNetPath
    Assert-DotNet8 -DotNetPath $dotnet -Publishing (-not $SkipPublish.IsPresent)
}
Assert-PsExec -Path $PsExecPath -AllowUnsigned $AllowUnsignedPsExec.IsPresent

$serviceIdentity = Resolve-ServiceIdentity
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

$appDir = Join-Path $InstallRoot 'app'
$appDataDir = Join-Path $appDir 'data'
$dataDir = Join-Path $InstallRoot 'data'
$logDir = Join-Path $InstallRoot 'logs'

Ensure-Directory $InstallRoot
Ensure-Directory $appDir
Ensure-Directory $appDataDir
Ensure-Directory $dataDir
Ensure-Directory $logDir
Ensure-Directory $CollectorSharePath

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$restartOnFailure = $existingService -and $existingService.Status -eq 'Running'

try {
    if ($existingService -and $existingService.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    if ($usingPublishedBundle) {
        foreach ($publishedItem in (Get-ChildItem -LiteralPath $PublishedAppPath -Force)) {
            Copy-Item -LiteralPath $publishedItem.FullName -Destination $appDir -Recurse -Force
        }
    }
    elseif (-not $SkipPublish) {
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

    $shareReaders = @($domainComputers.Name)
    if (-not [string]::IsNullOrWhiteSpace($serviceIdentity.ShareAccount)) {
        $shareReaders += $serviceIdentity.ShareAccount
    }
    Ensure-CollectorShare -Name $CollectorShareName -Path $CollectorSharePath -AdministratorsAccount $administratorsName -ReadAccounts $shareReaders

    $productionSettings = @{
        ConnectionStrings = @{ AuditDb = "Data Source=$dataDir\audit.db" }
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
            RemoteTempJsonPath = 'C:\temp\o365audit\o365-audit.json'
            DeviceTimeoutSeconds = 300
            MaxDeviceParallelism = 4
            JobPollingSeconds = 10
            DailyRunHour = 2
            DailyRunMinute = 15
            RetryMinutes = @(30, 120, 1440)
            FallbackTargets = $resolvedFallbackTargets
            DefaultOuFilter = ''
        }
        Copy = @{
            Enabled = $EnableArtifactCopy.IsPresent
            DefaultTargetRoot = $resolvedCopyTargetRoot
            AllowedTargetRoots = $resolvedAllowedCopyTargetRoots
            MaxParallelism = 2
            BufferSizeMb = 4
            VerifySha256 = $CopyVerifySha256.IsPresent
            MaxAttempts = 2
            PollingSeconds = 5
        }
    }
    $settingsPath = Join-Path $appDir 'appsettings.Production.json'
    $productionSettings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $settingsPath -Encoding utf8

    Set-ManagedDirectoryAcl -Path $InstallRoot -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute'
    Set-ManagedDirectoryAcl -Path $appDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute'
    Set-ManagedDirectoryAcl -Path $appDataDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
    Set-ManagedDirectoryAcl -Path $dataDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
    Set-ManagedDirectoryAcl -Path $logDir -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'Modify'
    Set-ManagedDirectoryAcl -Path $CollectorSharePath -AdministratorsSid $administratorsSid -SystemSid $systemSid -ServiceSid $serviceIdentity.AclSid -ServiceRights 'ReadAndExecute' -AdditionalReadSid $domainComputers.Sid

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
        "`"$applicationExe`" --environment Production --urls http://0.0.0.0:$Port"
    }
    else {
        if ([string]::IsNullOrWhiteSpace($dotnet)) {
            $dotnet = Resolve-DotNetPath
            Assert-DotNet8 -DotNetPath $dotnet -Publishing $false
        }
        "`"$dotnet`" `"$applicationDll`" --environment Production --urls http://0.0.0.0:$Port"
    }
    Configure-Service -Name $ServiceName -BinPath $binaryPath -Identity $serviceIdentity

    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

    $healthUri = "http://127.0.0.1:$Port/health"
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
}
catch {
    if ($restartOnFailure) {
        try {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Onceki servis yeniden baslatilamadi. Event Viewer ve servis kimligini kontrol edin."
        }
    }
    throw
}

Write-Host "Deployment tamamlandi." -ForegroundColor Green
Write-Host "Dashboard: http://$env:COMPUTERNAME`:$Port" -ForegroundColor Cyan
Write-Host "Collector share: \\$env:COMPUTERNAME\$CollectorShareName\collector.ps1" -ForegroundColor Cyan
Write-Host "Service: $ServiceName ($($serviceIdentity.Type): $($serviceIdentity.ScAccount))" -ForegroundColor Cyan
if ($EnableArtifactCopy) {
    Write-Host "Artifact copy: ENABLED -> $resolvedCopyTargetRoot (SHA256: $($CopyVerifySha256.IsPresent))" -ForegroundColor Yellow
}
else {
    Write-Host "Artifact copy: disabled (opt-in icin -EnableArtifactCopy gerekir)" -ForegroundColor DarkYellow
}
