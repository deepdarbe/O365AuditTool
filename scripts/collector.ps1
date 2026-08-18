[CmdletBinding()]
param([switch]$FunctionsOnly)

$ErrorActionPreference = 'Stop'

function Convert-ToMediaType {
    param(
        [string]$InterfaceType,
        [string]$Model,
        [string]$MediaHint,
        [string]$BusType
    )

    $text = @($Model, $MediaHint) -join ' '
    if ($text -match 'SSD|Solid State' -or $BusType -match 'NVMe') { return 'SSD' }
    if ($text -match 'HDD|Hard Disk|Fixed hard disk') { return 'HDD' }
    return 'Unknown'
}

function Convert-ToBusType {
    param(
        [string]$InterfaceType,
        [string]$Model,
        [string]$BusType
    )

    $text = @($BusType, $InterfaceType, $Model) -join ' '
    foreach ($candidate in @('NVMe', 'SATA', 'SAS', 'USB', 'RAID', 'SCSI', 'IDE', 'Virtual')) {
        if ($text -match [regex]::Escape($candidate)) { return $candidate }
    }

    return 'Unknown'
}

function Get-DeviceInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $ips = @()
    try {
        $ips = @(Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.NetAdapter.Status -eq 'Up' -and -not [bool]$_.NetAdapter.Virtual } |
            ForEach-Object { @($_.IPv4Address) } |
            Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } |
            Select-Object -ExpandProperty IPAddress -Unique)
    }
    catch {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and
                $_.IPAddress -notlike '169.254*' -and
                $_.IPAddress -ne '127.0.0.1'
            } |
            Select-Object -ExpandProperty IPAddress -Unique)
    }

    $currentLoggedOnUser = [string]$cs.UserName
    $lastLoggedOnUser = $null
    try {
        $lastLoggedOnUser = [string](Get-ItemProperty `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' `
            -Name LastLoggedOnUser `
            -ErrorAction Stop).LastLoggedOnUser
    }
    catch {}
    if ([string]::IsNullOrWhiteSpace($lastLoggedOnUser)) {
        $lastLoggedOnUser = $currentLoggedOnUser
    }

    [pscustomobject]@{
        hostname = $env:COMPUTERNAME
        serialNumber = $bios.SerialNumber
        os = "$($os.Caption) $($os.Version)"
        lastLoggedOnUser = $lastLoggedOnUser
        currentLoggedOnUser = $currentLoggedOnUser
        ips = @($ips)
        ou = $null
        site = $null
    }
}

function Get-StorageInfo {
    $volumes = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        [pscustomobject]@{
            name = $_.DeviceID
            totalBytes = [int64]$_.Size
            freeBytes = [int64]$_.FreeSpace
            fileSystem = $_.FileSystem
        }
    }

    $disks = @()

    try {
        $physical = Get-PhysicalDisk -ErrorAction Stop
        foreach ($d in $physical) {
            $bus = [string]$d.BusType
            $mediaHint = [string]$d.MediaType
            $busType = Convert-ToBusType -InterfaceType $bus -Model $d.FriendlyName -BusType $bus
            $mediaType = Convert-ToMediaType -InterfaceType $bus -Model $d.FriendlyName -MediaHint $mediaHint -BusType $busType
            $disks += [pscustomobject]@{
                model = $d.FriendlyName
                interfaceType = $bus
                busType = $busType
                mediaType = $mediaType
                sizeBytes = [int64]$d.Size
            }
        }
    }
    catch {
        $legacy = Get-CimInstance Win32_DiskDrive
        foreach ($d in $legacy) {
            $busType = Convert-ToBusType -InterfaceType $d.InterfaceType -Model $d.Model -BusType ''
            $mediaType = Convert-ToMediaType -InterfaceType $d.InterfaceType -Model $d.Model -MediaHint $d.MediaType -BusType $busType
            $disks += [pscustomobject]@{
                model = $d.Model
                interfaceType = $d.InterfaceType
                busType = $busType
                mediaType = $mediaType
                sizeBytes = [int64]$d.Size
            }
        }
    }

    [pscustomobject]@{
        volumes = @($volumes)
        disks = @($disks)
    }
}

function Get-OfficeProcessOwner {
    param([Parameter(Mandatory)][int]$ProcessId)

    try {
        $cimProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        $owner = Invoke-CimMethod -InputObject $cimProcess -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$owner.User)) {
            if ([string]::IsNullOrWhiteSpace([string]$owner.Domain)) {
                return [string]$owner.User
            }

            return "$($owner.Domain)\$($owner.User)"
        }
    }
    catch {}

    return $null
}

function Get-OfficeInfo {
    $regPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $products = @()
    foreach ($path in $regPaths) {
        foreach ($product in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
            if (-not $product.DisplayName -or $product.DisplayName -notmatch 'Microsoft 365|Microsoft Office|Office (?:2016|2019|2021|2024|LTSC)') {
                continue
            }

            $products += [pscustomobject]@{
                name = [string]$product.DisplayName
                version = [string]$product.DisplayVersion
                installType = [string]$product.ReleaseType
                architecture = if ($path -match 'WOW6432Node') { 'x86' } else { $null }
                updateChannel = $null
                productIds = $null
                updatesEnabled = $null
            }
        }
    }

    $clickToRunPath = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $clickToRun = Get-ItemProperty -LiteralPath $clickToRunPath -ErrorAction SilentlyContinue
    if ($null -ne $clickToRun) {
        $updatesEnabled = $null
        if ($null -ne $clickToRun.UpdatesEnabled) {
            $updatesEnabled = [string]$clickToRun.UpdatesEnabled -notmatch '^(?:0|false)$'
        }

        $version = [string]$clickToRun.VersionToReport
        if ([string]::IsNullOrWhiteSpace($version)) {
            $version = [string]$clickToRun.ClientVersionToReport
        }
        $updateChannel = [string]$clickToRun.UpdateChannel
        if ([string]::IsNullOrWhiteSpace($updateChannel)) {
            $updateChannel = [string]$clickToRun.CDNBaseUrl
        }

        $products += [pscustomobject]@{
            name = 'Microsoft Office Click-to-Run'
            version = $version
            installType = 'ClickToRun'
            architecture = [string]$clickToRun.Platform
            updateChannel = $updateChannel
            productIds = [string]$clickToRun.ProductReleaseIds
            updatesEnabled = $updatesEnabled
        }
    }

    $targetProcesses = @('OUTLOOK', 'WINWORD', 'EXCEL')
    $running = @()
    foreach ($name in $targetProcesses) {
        $processes = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        if ($processes.Count -eq 0) {
            $running += [pscustomobject]@{
                processName = $name
                pid = $null
                startTimeUtc = $null
                isRunning = $false
                owner = $null
                sessionId = $null
            }
        }
        else {
            foreach ($process in $processes) {
                $startTimeUtc = $null
                try { $startTimeUtc = $process.StartTime.ToUniversalTime().ToString('o') } catch {}

                $running += [pscustomobject]@{
                    processName = $name
                    pid = [int]$process.Id
                    startTimeUtc = $startTimeUtc
                    isRunning = $true
                    owner = Get-OfficeProcessOwner -ProcessId $process.Id
                    sessionId = [int]$process.SessionId
                }
            }
        }
    }

    [pscustomobject]@{
        installedProducts = @($products | Sort-Object name, version, installType -Unique)
        runningProcesses = @($running)
    }
}

function Test-UserProfileSid {
    param([AllowNull()][string]$Sid)

    return $Sid -match '^(?:S-1-5-21-\d+-\d+-\d+-\d+|S-1-12-1-\d+-\d+-\d+-\d+)$'
}

function Get-UserProfiles {
    $profilesBySid = @{}

    try {
        foreach ($profile in (Get-CimInstance Win32_UserProfile -ErrorAction Stop)) {
            if ($profile.Special -or -not (Test-UserProfileSid -Sid $profile.SID)) { continue }

            $profilesBySid[$profile.SID] = [pscustomobject]@{
                sid = [string]$profile.SID
                localPath = [Environment]::ExpandEnvironmentVariables([string]$profile.LocalPath)
                loaded = [bool]$profile.Loaded
                userName = $null
            }
        }
    }
    catch {
        Add-CollectorError -Message "profiles CIM: $($_.Exception.Message)"
    }

    # ProfileList is a useful fallback when CIM is unavailable or incomplete.
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    try {
        $profileKeys = @(Get-ChildItem -LiteralPath $profileListPath -ErrorAction Stop)
    }
    catch {
        Add-CollectorError -Message "profiles registry '$profileListPath': $($_.Exception.Message)"
        $profileKeys = @()
    }

    foreach ($key in $profileKeys) {
        $sid = [string]$key.PSChildName
        if (-not (Test-UserProfileSid -Sid $sid)) { continue }

        try {
            $profileData = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
        }
        catch {
            Add-CollectorError -Message "profiles registry [$sid] '$($key.PSPath)': $($_.Exception.Message)"
            continue
        }

        $localPath = [Environment]::ExpandEnvironmentVariables([string]$profileData.ProfileImagePath)
        if (-not $profilesBySid.ContainsKey($sid)) {
            $loadedState = Test-UserHiveLoaded -HiveName $sid -ErrorContext "profiles [$sid]"
            $profilesBySid[$sid] = [pscustomobject]@{
                sid = $sid
                localPath = $localPath
                loaded = $loadedState -eq $true
                userName = $null
            }
        }
        elseif ([string]::IsNullOrWhiteSpace($profilesBySid[$sid].localPath) -and $localPath) {
            $profilesBySid[$sid].localPath = $localPath
        }
    }

    foreach ($profile in $profilesBySid.Values) {
        $profile.userName = Resolve-ProfileUserName -Sid $profile.sid -ProfilePath $profile.localPath
    }

    return @($profilesBySid.Values | Sort-Object sid)
}

function Add-CollectorError {
    param([Parameter(Mandatory)][string]$Message)

    $normalizedMessage = if ($Message.Length -le 1000) { $Message } else { $Message.Substring(0, 1000) }
    if (@($script:errors).Count -ge 200) {
        $truncationMessage = 'collector: additional errors were truncated after 200 entries'
        if (@($script:errors) -notcontains $truncationMessage) {
            $script:errors = @($script:errors) + $truncationMessage
        }
        return
    }

    if (@($script:errors) -notcontains $normalizedMessage) {
        $script:errors = @($script:errors) + $normalizedMessage
    }
}

function Resolve-ProfileUserName {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [string]$ProfilePath
    )

    try {
        $securityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        return $securityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) {
            return Split-Path -Path $ProfilePath -Leaf
        }

        return $null
    }
}

function Test-LegacyScanRoot {
    param(
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Sid
    )

    $currentPath = $ProfilePath
    $pathParts = @($RelativePath -split '[\\/]' | Where-Object { $_ })

    try {
        $profileDirectory = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if (
            -not $profileDirectory.PSIsContainer -or
            ($profileDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            return $false
        }
    }
    catch {
        if (
            $_.Exception -isnot [System.Management.Automation.ItemNotFoundException] -and
            $_.FullyQualifiedErrorId -notmatch 'PathNotFound|ItemNotFound'
        ) {
            Add-CollectorError -Message "legacyFiles [$Sid] access '$currentPath': $($_.Exception.Message)"
        }
        return $false
    }

    foreach ($pathPart in $pathParts) {
        $currentPath = Join-Path $currentPath $pathPart
        try {
            $directory = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
            if (
                -not $directory.PSIsContainer -or
                ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                return $false
            }
        }
        catch {
            if (
                $_.Exception -isnot [System.Management.Automation.ItemNotFoundException] -and
                $_.FullyQualifiedErrorId -notmatch 'PathNotFound|ItemNotFound'
            ) {
                Add-CollectorError -Message "legacyFiles [$Sid] access '$currentPath': $($_.Exception.Message)"
            }
            return $false
        }
    }

    return $true
}

function Get-LegacyOutlookFiles {
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$Sid
    )

    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($RootPath)

    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Pop()
        try {
            $children = @(Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop)
        }
        catch {
            Add-CollectorError -Message "legacyFiles [$Sid] access '$currentDirectory': $($_.Exception.Message)"
            continue
        }

        foreach ($child in $children) {
            try {
                if ($child.PSIsContainer) {
                    if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                        $pendingDirectories.Push($child.FullName)
                    }
                    continue
                }

                if ($child.Extension -in @('.nk2', '.n2k')) {
                    $child
                }
            }
            catch {
                Add-CollectorError -Message "legacyFiles [$Sid] access '$($child.FullName)': $($_.Exception.Message)"
            }
        }
    }
}

function Get-OutlookPstFiles {
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$Sid
    )

    try {
        $root = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
        if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return
        }
    }
    catch {
        if (
            $_.Exception -isnot [System.Management.Automation.ItemNotFoundException] -and
            $_.FullyQualifiedErrorId -notmatch 'PathNotFound|ItemNotFound'
        ) {
            Add-CollectorError -Message "pstFiles [$Sid] fallback access '$RootPath': $($_.Exception.Message)"
        }
        return
    }

    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($RootPath)

    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Pop()
        try {
            $children = @(Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop)
        }
        catch {
            Add-CollectorError -Message "pstFiles [$Sid] fallback access '$currentDirectory': $($_.Exception.Message)"
            continue
        }

        foreach ($child in $children) {
            try {
                if ($child.PSIsContainer) {
                    if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                        $pendingDirectories.Push($child.FullName)
                    }
                    continue
                }

                if ($child.Extension -eq '.pst') {
                    $child
                }
            }
            catch {
                Add-CollectorError -Message "pstFiles [$Sid] fallback access '$($child.FullName)': $($_.Exception.Message)"
            }
        }
    }
}

function Test-UserHiveLoaded {
    param(
        [Parameter(Mandatory)][string]$HiveName,
        [string]$ErrorContext = 'outlook'
    )

    $usersKey = $null
    $hiveKey = $null
    try {
        $usersKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::Users,
            [Microsoft.Win32.RegistryView]::Default
        )
        $hiveKey = $usersKey.OpenSubKey($HiveName, $false)
        return $null -ne $hiveKey
    }
    catch {
        Add-CollectorError -Message "$ErrorContext hive state '$HiveName': $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($null -ne $hiveKey) { $hiveKey.Dispose() }
        if ($null -ne $usersKey) { $usersKey.Dispose() }
    }
}

function Mount-UserHive {
    param(
        [Parameter(Mandatory)][string]$NtUserPath,
        [Parameter(Mandatory)][string]$HiveName,
        [Parameter(Mandatory)][string]$Sid
    )

    try {
        if (-not (Test-Path -LiteralPath $NtUserPath -PathType Leaf -ErrorAction Stop)) {
            Add-CollectorError -Message "outlook [$Sid] hive mount '$NtUserPath': NTUSER.DAT was not found"
            return $false
        }

        $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
        $output = @(& $regExe load "HKU\$HiveName" $NtUserPath 2>&1)
        # A successful reg.exe load means this script owns the temporary hive and must unload it.
        if ($LASTEXITCODE -eq 0) { return $true }

        Add-CollectorError -Message "outlook [$Sid] hive mount '$NtUserPath': reg.exe exit $LASTEXITCODE $($output -join ' ')"
        return $false
    }
    catch {
        Add-CollectorError -Message "outlook [$Sid] hive mount '$NtUserPath': $($_.Exception.Message)"
        return $false
    }
}

function Dismount-UserHive {
    param(
        [Parameter(Mandatory)][string]$HiveName,
        [Parameter(Mandatory)][string]$Sid
    )

    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    $lastOutput = @()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            # Release any finalized registry handles before asking Windows to unload the hive.
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            $lastOutput = @(& $regExe unload "HKU\$HiveName" 2>&1)
            $exitCode = $LASTEXITCODE
            if ($exitCode -eq 0) {
                return $true
            }

            $loadedState = Test-UserHiveLoaded -HiveName $HiveName -ErrorContext "outlook [$Sid]"
            if ($loadedState -eq $false) {
                return $true
            }
        }
        catch {
            $lastOutput = @($_.Exception.Message)
        }
        Start-Sleep -Milliseconds 150
    }

    Add-CollectorError -Message "outlook [$Sid] hive unload 'HKU\$HiveName': $($lastOutput -join ' ')"
    return $false
}

function Convert-RegistryValueToText {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return @() }

    $rawCandidates = @()
    if ($Value -is [byte[]]) {
        if ($Value.Length -gt 0) {
            $rawCandidates += [Text.Encoding]::Unicode.GetString($Value)
            $rawCandidates += [Text.Encoding]::ASCII.GetString($Value)
            $rawCandidates += [Text.Encoding]::UTF8.GetString($Value)
        }
    }
    elseif ($Value -is [string[]]) {
        $rawCandidates += $Value
    }
    elseif ($Value -is [string]) {
        $rawCandidates += $Value
    }
    else {
        return @()
    }

    $seen = @{}
    foreach ($candidate in $rawCandidates) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }

        # Binary MAPI values often contain NUL separators around useful text.
        $clean = ([string]$candidate) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' '
        $clean = $clean.Trim()
        if (-not $clean) { continue }

        $key = $clean.ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $clean
        }
    }
}

function Get-RegistryTextEntries {
    param(
        [Parameter(Mandatory)][Microsoft.Win32.RegistryKey]$RegistryKey,
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$ErrorContext
    )

    try {
        $valueNames = @($RegistryKey.GetValueNames())
    }
    catch {
        Add-CollectorError -Message "$ErrorContext registry values '$KeyPath': $($_.Exception.Message)"
        $valueNames = @()
    }

    foreach ($valueName in $valueNames) {
        try {
            $value = $RegistryKey.GetValue(
                $valueName,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            foreach ($text in (Convert-RegistryValueToText -Value $value)) {
                [pscustomobject]@{
                    keyPath = $KeyPath
                    valueName = [string]$valueName
                    text = $text
                }
            }
        }
        catch {
            Add-CollectorError -Message "$ErrorContext registry value '$KeyPath\$valueName': $($_.Exception.Message)"
        }
    }

    try {
        $subKeyNames = @($RegistryKey.GetSubKeyNames())
    }
    catch {
        Add-CollectorError -Message "$ErrorContext registry subkeys '$KeyPath': $($_.Exception.Message)"
        $subKeyNames = @()
    }

    foreach ($subKeyName in $subKeyNames) {
        $subKey = $null
        try {
            $subKey = $RegistryKey.OpenSubKey($subKeyName, $false)
            if ($null -ne $subKey) {
                Get-RegistryTextEntries -RegistryKey $subKey -KeyPath "$KeyPath\$subKeyName" -ErrorContext $ErrorContext
            }
            else {
                Add-CollectorError -Message "$ErrorContext registry open '$KeyPath\$subKeyName': key became unavailable"
            }
        }
        catch {
            Add-CollectorError -Message "$ErrorContext registry open '$KeyPath\$subKeyName': $($_.Exception.Message)"
        }
        finally {
            if ($null -ne $subKey) { $subKey.Dispose() }
        }
    }
}

function Resolve-UserPstPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ProfilePath
    )

    $resolved = $Path.Trim().Trim('"').Trim("'") -replace '/', '\'
    if ($ProfilePath) {
        $localAppData = Join-Path $ProfilePath 'AppData\Local'
        $roamingAppData = Join-Path $ProfilePath 'AppData\Roaming'
        $resolved = $resolved -replace '(?i)%USERPROFILE%', [regex]::Escape($ProfilePath)
        $resolved = $resolved -replace '(?i)%LOCALAPPDATA%', [regex]::Escape($localAppData)
        $resolved = $resolved -replace '(?i)%APPDATA%', [regex]::Escape($roamingAppData)
        $resolved = $resolved -replace '\\\\', '\'
        if ($Path -match '^\\\\') {
            $resolved = "\\$($resolved.TrimStart('\'))"
        }
    }

    return [Environment]::ExpandEnvironmentVariables($resolved).Trim()
}

function Find-PstPathsInText {
    param(
        [Parameter(Mandatory)][string]$Text,
        [string]$ProfilePath
    )

    $patterns = @(
        '(?i)(?<path>[A-Z]:\\[^"\x00\r\n<>|]*?\.pst)',
        '(?i)(?<path>\\\\[^\\\x00\r\n<>|]+\\[^\\\x00\r\n<>|]+\\[^"\x00\r\n<>|]*?\.pst)',
        '(?i)(?<path>%(?:USERPROFILE|LOCALAPPDATA|APPDATA)%\\[^"\x00\r\n<>|]*?\.pst)'
    )

    $seen = @{}
    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($Text, $pattern)) {
            $path = Resolve-UserPstPath -Path $match.Groups['path'].Value -ProfilePath $ProfilePath
            if (-not $path) { continue }

            $key = $path.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $path
            }
        }
    }
}

function Get-AccountType {
    param([Parameter(Mandatory)][string]$Context)

    if ($Context -match '(?i)\bimap\b') { return 'IMAP' }
    if ($Context -match '(?i)\bpop3?\b') { return 'POP' }
    if ($Context -match '(?i)exchange|mapi|msems|office\s*365|microsoft\s*365') { return 'Exchange' }
    return 'Unknown'
}

function Test-AccountRegistryEntry {
    param([Parameter(Mandatory)]$Entry)

    $mapiAccountValues = @(
        '001e3001', '001f3001',
        '001e39fe', '001f39fe',
        '001e6600', '001f6600',
        '001e6641', '001f6641'
    )

    if ($Entry.keyPath -match '(?i)\\GroupsStore(?:\\|$)') { return $false }
    if ($Entry.valueName -in $mapiAccountValues) { return $true }
    return $Entry.valueName -match '(?i)account\s*name|email\s*address|smtp\s*address|user\s*email'
}

function Resolve-AccountAddress {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory)][string]$Sid,
        [AllowNull()][string]$ProfileName
    )

    $sidAccounts = @($Accounts | Where-Object {
        $_.sid -eq $Sid -and -not [string]::IsNullOrWhiteSpace([string]$_.address)
    })

    if (-not [string]::IsNullOrWhiteSpace($ProfileName)) {
        $profileAddresses = @($sidAccounts |
            Where-Object { $_.profileName -eq $ProfileName } |
            Select-Object -ExpandProperty address -Unique)

        if ($profileAddresses.Count -eq 1) { return [string]$profileAddresses[0] }
        if ($profileAddresses.Count -gt 1) { return $null }
    }

    $sidAddresses = @($sidAccounts | Select-Object -ExpandProperty address -Unique)
    if ($sidAddresses.Count -eq 1) { return [string]$sidAddresses[0] }
    return $null
}

function Get-DefaultOutlookProfileNames {
    param(
        [Parameter(Mandatory)][Microsoft.Win32.RegistryKey]$UsersKey,
        [Parameter(Mandatory)][string]$HiveName,
        [Parameter(Mandatory)][string]$Sid
    )

    $defaultProfileRoots = @(
        'Software\Microsoft\Office\16.0\Outlook',
        'Software\Microsoft\Office\15.0\Outlook',
        'Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles'
    )
    $names = @()
    foreach ($relativeRoot in $defaultProfileRoots) {
        $key = $null
        try {
            $key = $UsersKey.OpenSubKey("$HiveName\$relativeRoot", $false)
            if ($null -eq $key) { continue }
            $value = $key.GetValue('DefaultProfile', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $names += @(Convert-RegistryValueToText -Value $value)
        }
        catch {
            Add-CollectorError -Message "outlook [$Sid] default profile '$relativeRoot': $($_.Exception.Message)"
        }
        finally {
            if ($null -ne $key) { $key.Dispose() }
        }
    }

    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Get-OutlookProfileInfo {
    $profileResults = @{}
    $accountResults = @{}
    $pstCandidates = @{}
    $legacyCandidates = @{}
    $emailPattern = '[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+'
    $profileRoots = @(
        'Software\Microsoft\Office\16.0\Outlook\Profiles',
        'Software\Microsoft\Office\15.0\Outlook\Profiles',
        'Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles'
    )

    foreach ($userProfile in (Get-UserProfiles)) {
        $sid = [string]$userProfile.sid
        $profilePath = [string]$userProfile.localPath
        $userName = [string]$userProfile.userName
        $profileLoaded = [bool]$userProfile.loaded
        $windowsProfileKey = "$sid|"
        $profileResults[$windowsProfileKey] = [pscustomobject]@{
            sid = $sid
            profileName = ''
            profilePath = $profilePath
            userName = $userName
            loaded = $profileLoaded
            isDefault = $false
        }
        $hiveName = $sid
        $loadedByCollector = $false
        $hiveState = Test-UserHiveLoaded -HiveName $hiveName -ErrorContext "outlook [$sid]"
        $canScanRegistry = $hiveState -eq $true

        try {
            if (-not $canScanRegistry -and $profilePath) {
                $hiveName = "O365Audit_$([Guid]::NewGuid().ToString('N'))"
                $ntUserPath = Join-Path $profilePath 'NTUSER.DAT'
                $loadedByCollector = Mount-UserHive -NtUserPath $ntUserPath -HiveName $hiveName -Sid $sid
                $canScanRegistry = $loadedByCollector
            }
            elseif (-not $canScanRegistry) {
                Add-CollectorError -Message "outlook [$sid] hive mount: Windows profile path is unavailable"
            }

            if ($canScanRegistry) {
                $usersKey = $null
                try {
                    $usersKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::Users,
                        [Microsoft.Win32.RegistryView]::Default
                    )
                    $defaultProfileNames = @(Get-DefaultOutlookProfileNames -UsersKey $usersKey -HiveName $hiveName -Sid $sid)

                    foreach ($relativeRoot in $profileRoots) {
                        $rootKey = $null
                        try {
                            $rootKey = $usersKey.OpenSubKey("$hiveName\$relativeRoot", $false)
                            if ($null -eq $rootKey) { continue }

                            foreach ($profileName in $rootKey.GetSubKeyNames()) {
                                $profileKey = $null
                                try {
                                    $profileKey = $rootKey.OpenSubKey($profileName, $false)
                                    if ($null -eq $profileKey) { continue }

                                    $profileDedupKey = "$sid|$($profileName.ToLowerInvariant())"
                                    if (-not $profileResults.ContainsKey($profileDedupKey)) {
                                        $null = $profileResults.Remove($windowsProfileKey)
                                        $profileResults[$profileDedupKey] = [pscustomobject]@{
                                            sid = $sid
                                            profileName = $profileName
                                            profilePath = $profilePath
                                            userName = $userName
                                            loaded = $profileLoaded
                                            isDefault = @($defaultProfileNames) -contains $profileName
                                        }
                                    }
                                    elseif (@($defaultProfileNames) -contains $profileName) {
                                        $profileResults[$profileDedupKey].isDefault = $true
                                    }

                                $entries = @(Get-RegistryTextEntries -RegistryKey $profileKey -KeyPath "$relativeRoot\$profileName" -ErrorContext "outlook [$sid][$profileName]")
                                $contextByKey = @{}
                                foreach ($contextEntry in $entries) {
                                    if (-not $contextByKey.ContainsKey($contextEntry.keyPath)) {
                                        $contextByKey[$contextEntry.keyPath] = [System.Collections.Generic.List[string]]::new()
                                    }
                                    $contextByKey[$contextEntry.keyPath].Add("$($contextEntry.valueName) $($contextEntry.text)")
                                }

                                foreach ($entry in $entries) {
                                    foreach ($pstPath in (Find-PstPathsInText -Text $entry.text -ProfilePath $profilePath)) {
                                        $pstKey = "$sid|$($pstPath.ToLowerInvariant())"
                                        if (-not $pstCandidates.ContainsKey($pstKey)) {
                                                $pstCandidates[$pstKey] = [pscustomobject]@{
                                                    sid = $sid
                                                    profileName = $profileName
                                                    path = $pstPath
                                                }
                                        }
                                        elseif (
                                            -not [string]::IsNullOrWhiteSpace([string]$pstCandidates[$pstKey].profileName) -and
                                            $pstCandidates[$pstKey].profileName -ne $profileName
                                        ) {
                                            # One physical PST referenced by multiple profiles has no unambiguous account owner.
                                            $pstCandidates[$pstKey].profileName = $null
                                        }
                                    }

                                    if (-not (Test-AccountRegistryEntry -Entry $entry)) { continue }
                                    $context = "$($entry.keyPath) $($contextByKey[$entry.keyPath] -join ' ')"
                                    foreach ($emailMatch in [regex]::Matches($entry.text, $emailPattern)) {
                                        $email = $emailMatch.Value.Trim().ToLowerInvariant()
                                        if ($email -match '^(?:exchange|mailbox|archive)guid\+') { continue }

                                        $accountType = Get-AccountType -Context $context
                                        $accountKey = "$sid|$($profileName.ToLowerInvariant())|$email"
                                        if (-not $accountResults.ContainsKey($accountKey)) {
                                            $accountResults[$accountKey] = [pscustomobject]@{
                                                sid = $sid
                                                    profileName = $profileName
                                                    accountType = $accountType
                                                    address = $email
                                                    isActive = $profileLoaded -and (@($defaultProfileNames) -contains $profileName)
                                            }
                                        }
                                        elseif (
                                            $accountResults[$accountKey].accountType -eq 'Unknown' -and
                                            $accountType -ne 'Unknown'
                                        ) {
                                            $accountResults[$accountKey].accountType = $accountType
                                        }
                                        if ($profileLoaded -and (@($defaultProfileNames) -contains $profileName)) {
                                            $accountResults[$accountKey].isActive = $true
                                        }
                                    }
                                }
                                }
                                catch {
                                    Add-CollectorError -Message "outlook [$sid][$profileName] registry: $($_.Exception.Message)"
                                }
                                finally {
                                    if ($null -ne $profileKey) { $profileKey.Dispose() }
                                }
                            }
                        }
                        catch {
                            Add-CollectorError -Message "outlook [$sid] registry root '$relativeRoot': $($_.Exception.Message)"
                        }
                        finally {
                            if ($null -ne $rootKey) { $rootKey.Dispose() }
                        }
                    }
                }
                finally {
                    if ($null -ne $usersKey) { $usersKey.Dispose() }
                }
            }
        }
        catch {
            Add-CollectorError -Message "outlook [$sid] registry scan: $($_.Exception.Message)"
        }
        finally {
            if ($loadedByCollector) {
                $null = Dismount-UserHive -HiveName $hiveName -Sid $sid
            }
        }

        # Registry data may be absent or stale, so inspect only standard PST locations.
        if ($profilePath) {
            try {
                $profileDirectory = Get-Item -LiteralPath $profilePath -Force -ErrorAction Stop
                $profilePathAccessible = $profileDirectory.PSIsContainer -and
                    ($profileDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
                if (-not $profilePathAccessible) {
                    Add-CollectorError -Message "profiles [$sid] path '$profilePath': path is not a regular directory"
                }
            }
            catch {
                $profilePathAccessible = $false
                Add-CollectorError -Message "profiles [$sid] path '$profilePath': $($_.Exception.Message)"
            }

            if ($profilePathAccessible) {
                $fallbackDirectories = @(
                    (Join-Path $profilePath 'Documents\Outlook Files'),
                    (Join-Path $profilePath 'AppData\Local\Microsoft\Outlook'),
                    (Join-Path $profilePath 'Local Settings\Application Data\Microsoft\Outlook')
                )

                foreach ($directory in ($fallbackDirectories | Select-Object -Unique)) {
                    foreach ($file in (Get-OutlookPstFiles -RootPath $directory -Sid $sid)) {
                        $pstKey = "$sid|$($file.FullName.ToLowerInvariant())"
                        if (-not $pstCandidates.ContainsKey($pstKey)) {
                            $pstCandidates[$pstKey] = [pscustomobject]@{
                                sid = $sid
                                profileName = $null
                                path = $file.FullName
                            }
                        }
                    }
                }

                $legacyDirectories = @(
                    'AppData\Roaming\Microsoft\Outlook',
                    'AppData\Local\Microsoft\Outlook',
                    'Application Data\Microsoft\Outlook',
                    'Documents\Outlook Files'
                )

                foreach ($relativeDirectory in $legacyDirectories) {
                    if (-not (Test-LegacyScanRoot -ProfilePath $profilePath -RelativePath $relativeDirectory -Sid $sid)) {
                        continue
                    }

                    $legacyRoot = Join-Path $profilePath $relativeDirectory
                    foreach ($file in (Get-LegacyOutlookFiles -RootPath $legacyRoot -Sid $sid)) {
                        try {
                            $fullPath = [IO.Path]::GetFullPath($file.FullName)
                            $legacyKey = "$sid|$($fullPath.ToLowerInvariant())"
                            if (-not $legacyCandidates.ContainsKey($legacyKey)) {
                                $legacyCandidates[$legacyKey] = [pscustomobject]@{
                                    sid = $sid
                                    userName = $userName
                                    profileName = $file.BaseName
                                    artifactType = $file.Extension.TrimStart('.').ToUpperInvariant()
                                    path = $fullPath
                                }
                            }
                        }
                        catch {
                            Add-CollectorError -Message "legacyFiles [$sid] access '$($file.FullName)': $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
        else {
            Add-CollectorError -Message "profiles [$sid] path: Windows profile path is unavailable"
        }

        $outlookProfilesForSid = @($profileResults.Values | Where-Object {
            $_.sid -eq $sid -and -not [string]::IsNullOrWhiteSpace([string]$_.profileName)
        })
        if (
            $outlookProfilesForSid.Count -eq 1 -and
            -not ($outlookProfilesForSid | Where-Object { $_.isDefault })
        ) {
            $singleProfileName = [string]$outlookProfilesForSid[0].profileName
            $outlookProfilesForSid[0].isDefault = $true
            if ($profileLoaded) {
                foreach ($account in $accountResults.Values) {
                    if ($account.sid -eq $sid -and $account.profileName -eq $singleProfileName) {
                        $account.isActive = $true
                    }
                }
            }
        }
    }

    $accounts = @($accountResults.Values | Sort-Object sid, profileName, address, accountType)
    $pstFiles = foreach ($entry in ($pstCandidates.Values | Sort-Object sid, path)) {
        $fileInfo = $null
        try {
            $fileInfo = Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
        }
        catch {
            if (
                $_.Exception -isnot [System.Management.Automation.ItemNotFoundException] -and
                $_.FullyQualifiedErrorId -notmatch 'PathNotFound|ItemNotFound'
            ) {
                Add-CollectorError -Message "pstFiles [$($entry.sid)] access '$($entry.path)': $($_.Exception.Message)"
            }
        }
        $exists = $null -ne $fileInfo -and -not $fileInfo.PSIsContainer
        $upn = Resolve-AccountAddress -Accounts $accounts -Sid $entry.sid -ProfileName $entry.profileName

        [pscustomobject]@{
            sid = $entry.sid
            userPrincipalName = $upn
            profileName = $entry.profileName
            path = $entry.path
            sizeBytes = if ($exists) { [int64]$fileInfo.Length } else { [int64]0 }
            existsOnDisk = [bool]$exists
            lastWriteUtc = if ($exists) { $fileInfo.LastWriteTimeUtc.ToString('o') } else { $null }
        }
    }

    $legacyFiles = foreach ($entry in ($legacyCandidates.Values | Sort-Object sid, path)) {
        $matchingProfileNames = @($profileResults.Values |
            Where-Object { $_.sid -eq $entry.sid -and $_.profileName -eq $entry.profileName } |
            Select-Object -ExpandProperty profileName -Unique)
        $resolvedProfileName = if ($matchingProfileNames.Count -eq 1) {
            [string]$matchingProfileNames[0]
        }
        else {
            $null
        }
        $upn = Resolve-AccountAddress -Accounts $accounts -Sid $entry.sid -ProfileName $resolvedProfileName
        $fileInfo = $null

        try {
            $fileInfo = Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
            if ($fileInfo.PSIsContainer) {
                $fileInfo = $null
            }
        }
        catch {
            Add-CollectorError -Message "legacyFiles [$($entry.sid)] access '$($entry.path)': $($_.Exception.Message)"
        }

        [pscustomobject]@{
            sid = $entry.sid
            userName = $entry.userName
            userPrincipalName = $upn
            profileName = $resolvedProfileName
            artifactType = $entry.artifactType
            path = $entry.path
            sizeBytes = if ($null -ne $fileInfo) { [int64]$fileInfo.Length } else { [int64]0 }
            existsOnDisk = $null -ne $fileInfo
            lastWriteUtc = if ($null -ne $fileInfo) { $fileInfo.LastWriteTimeUtc.ToString('o') } else { $null }
        }
    }

    [pscustomobject]@{
        profiles = @($profileResults.Values | Sort-Object sid, profileName)
        mailAccounts = $accounts
        pstFiles = @($pstFiles)
        legacyFiles = @($legacyFiles)
    }
}

if ($FunctionsOnly) { return }

$started = Get-Date
$errors = @()

try { $device = Get-DeviceInfo } catch { $errors += "device: $($_.Exception.Message)"; $device = [pscustomobject]@{ hostname=$env:COMPUTERNAME; serialNumber=$null; os=$null; lastLoggedOnUser=$null; currentLoggedOnUser=$null; ips=@(); ou=$null; site=$null } }
try { $storage = Get-StorageInfo } catch { $errors += "storage: $($_.Exception.Message)"; $storage = [pscustomobject]@{ volumes=@(); disks=@() } }
try { $office = Get-OfficeInfo } catch { $errors += "office: $($_.Exception.Message)"; $office = [pscustomobject]@{ installedProducts=@(); runningProcesses=@() } }
try { $mail = Get-OutlookProfileInfo } catch { $errors += "outlook: $($_.Exception.Message)"; $mail = [pscustomobject]@{ profiles=@(); mailAccounts=@(); pstFiles=@(); legacyFiles=@() } }

$duration = [int]((Get-Date) - $started).TotalMilliseconds

$payload = [ordered]@{
    schemaVersion = '1.3'
    device = $device
    storage = $storage
    office = $office
    profiles = $mail.profiles
    mailAccounts = $mail.mailAccounts
    pstFiles = $mail.pstFiles
    legacyFiles = @($mail.legacyFiles)
    scanMeta = [ordered]@{
        scanTimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        durationMs = $duration
    }
    errors = @($errors)
}

$payload | ConvertTo-Json -Depth 8 -Compress
