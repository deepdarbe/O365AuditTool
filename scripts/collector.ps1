[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Convert-ToMediaType {
    param(
        [string]$InterfaceType,
        [string]$Model,
        [string]$MediaHint,
        [string]$BusType
    )

    $text = @($InterfaceType, $Model, $MediaHint, $BusType) -join ' '
    if ($text -match 'NVMe') { return 'NVMe' }
    if ($text -match 'SSD|Solid State') { return 'SSD' }
    if ($text -match 'SATA') { return 'SATA' }
    if ($text -match 'SCSI|RAID|SAS') { return 'SATA' }
    return 'Unknown'
}

function Get-DeviceInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } |
        Select-Object -ExpandProperty IPAddress -Unique

    [pscustomobject]@{
        hostname = $env:COMPUTERNAME
        serialNumber = $bios.SerialNumber
        os = "$($os.Caption) $($os.Version)"
        lastLoggedOnUser = $cs.UserName
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
            $mediaType = Convert-ToMediaType -InterfaceType $bus -Model $d.FriendlyName -MediaHint $mediaHint -BusType $bus
            $disks += [pscustomobject]@{
                model = $d.FriendlyName
                interfaceType = $bus
                mediaType = $mediaType
                sizeBytes = [int64]$d.Size
            }
        }
    }
    catch {
        $legacy = Get-CimInstance Win32_DiskDrive
        foreach ($d in $legacy) {
            $mediaType = Convert-ToMediaType -InterfaceType $d.InterfaceType -Model $d.Model -MediaHint $d.MediaType -BusType ''
            $disks += [pscustomobject]@{
                model = $d.Model
                interfaceType = $d.InterfaceType
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

function Get-OfficeInfo {
    $regPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $products = foreach ($path in $regPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -and (
                    $_.DisplayName -match 'Microsoft 365' -or
                    $_.DisplayName -match 'Microsoft Office' -or
                    $_.DisplayName -match 'Office 2016' -or
                    $_.DisplayName -match 'Office 2019' -or
                    $_.DisplayName -match 'Office 2021'
                )
            } |
            Select-Object @{n='name';e={$_.DisplayName}}, @{n='version';e={$_.DisplayVersion}}, @{n='installType';e={$_.ReleaseType}}
    }

    $targetProcesses = @('OUTLOOK', 'WINWORD', 'EXCEL')
    $running = @()
    foreach ($name in $targetProcesses) {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $p) {
            $running += [pscustomobject]@{
                processName = $name
                pid = $null
                startTimeUtc = $null
                isRunning = $false
            }
        }
        else {
            $running += [pscustomobject]@{
                processName = $name
                pid = [int]$p.Id
                startTimeUtc = $p.StartTime.ToUniversalTime().ToString('o')
                isRunning = $true
            }
        }
    }

    [pscustomobject]@{
        installedProducts = @($products | Sort-Object name -Unique)
        runningProcesses = @($running)
    }
}

function Get-UserProfiles {
    $profilesBySid = @{}

    try {
        foreach ($profile in (Get-CimInstance Win32_UserProfile -ErrorAction Stop)) {
            if ($profile.Special -or $profile.SID -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }

            $profilesBySid[$profile.SID] = [pscustomobject]@{
                sid = [string]$profile.SID
                localPath = [Environment]::ExpandEnvironmentVariables([string]$profile.LocalPath)
                loaded = [bool]$profile.Loaded
            }
        }
    }
    catch {}

    # ProfileList is a useful fallback when CIM is unavailable or incomplete.
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($key in (Get-ChildItem -LiteralPath $profileListPath -ErrorAction SilentlyContinue)) {
        $sid = [string]$key.PSChildName
        if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }

        $profileData = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
        $localPath = [Environment]::ExpandEnvironmentVariables([string]$profileData.ProfileImagePath)
        if (-not $profilesBySid.ContainsKey($sid)) {
            $profilesBySid[$sid] = [pscustomobject]@{
                sid = $sid
                localPath = $localPath
                loaded = $false
            }
        }
        elseif ([string]::IsNullOrWhiteSpace($profilesBySid[$sid].localPath) -and $localPath) {
            $profilesBySid[$sid].localPath = $localPath
        }
    }

    return @($profilesBySid.Values | Sort-Object sid)
}

function Add-CollectorError {
    param([Parameter(Mandatory)][string]$Message)

    $script:errors = @($script:errors) + $Message
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

function Test-UserHiveLoaded {
    param([Parameter(Mandatory)][string]$HiveName)

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
        return $false
    }
    finally {
        if ($null -ne $hiveKey) { $hiveKey.Dispose() }
        if ($null -ne $usersKey) { $usersKey.Dispose() }
    }
}

function Mount-UserHive {
    param(
        [Parameter(Mandatory)][string]$NtUserPath,
        [Parameter(Mandatory)][string]$HiveName
    )

    try {
        if (-not (Test-Path -LiteralPath $NtUserPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            return $false
        }

        $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
        & $regExe load "HKU\$HiveName" $NtUserPath *> $null
        # A successful reg.exe load means this script owns the temporary hive and must unload it.
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Dismount-UserHive {
    param([Parameter(Mandatory)][string]$HiveName)

    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        # Release any finalized registry handles before asking Windows to unload the hive.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        & $regExe unload "HKU\$HiveName" *> $null
        if ($LASTEXITCODE -eq 0 -or -not (Test-UserHiveLoaded -HiveName $HiveName)) {
            return
        }
        Start-Sleep -Milliseconds 150
    }

    Write-Warning "Unable to unload temporary user hive HKU\$HiveName after three attempts."
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
        [Parameter(Mandatory)][string]$KeyPath
    )

    foreach ($valueName in $RegistryKey.GetValueNames()) {
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
        catch {}
    }

    foreach ($subKeyName in $RegistryKey.GetSubKeyNames()) {
        $subKey = $null
        try {
            $subKey = $RegistryKey.OpenSubKey($subKeyName, $false)
            if ($null -ne $subKey) {
                Get-RegistryTextEntries -RegistryKey $subKey -KeyPath "$KeyPath\$subKeyName"
            }
        }
        catch {}
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
        $hiveName = $sid
        $loadedByCollector = $false
        $canScanRegistry = Test-UserHiveLoaded -HiveName $hiveName

        try {
            if (-not $canScanRegistry -and $profilePath) {
                $hiveName = "O365Audit_$([Guid]::NewGuid().ToString('N'))"
                $ntUserPath = Join-Path $profilePath 'NTUSER.DAT'
                $loadedByCollector = Mount-UserHive -NtUserPath $ntUserPath -HiveName $hiveName
                $canScanRegistry = $loadedByCollector
            }

            if ($canScanRegistry) {
                $usersKey = $null
                try {
                    $usersKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::Users,
                        [Microsoft.Win32.RegistryView]::Default
                    )

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
                                        $profileResults[$profileDedupKey] = [pscustomobject]@{
                                            sid = $sid
                                            profileName = $profileName
                                        }
                                    }

                                $entries = @(Get-RegistryTextEntries -RegistryKey $profileKey -KeyPath "$relativeRoot\$profileName")
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
                                            }
                                        }
                                        elseif (
                                            $accountResults[$accountKey].accountType -eq 'Unknown' -and
                                            $accountType -ne 'Unknown'
                                        ) {
                                            $accountResults[$accountKey].accountType = $accountType
                                        }
                                    }
                                }
                                }
                                catch {}
                                finally {
                                    if ($null -ne $profileKey) { $profileKey.Dispose() }
                                }
                            }
                        }
                        catch {}
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
        catch {}
        finally {
            if ($loadedByCollector) {
                Dismount-UserHive -HiveName $hiveName
            }
        }

        # Registry data may be absent or stale, so inspect only standard PST locations.
        if ($profilePath) {
            $fallbackDirectories = @(
                (Join-Path $profilePath 'Documents\Outlook Files'),
                (Join-Path $profilePath 'AppData\Local\Microsoft\Outlook'),
                (Join-Path $profilePath 'Local Settings\Application Data\Microsoft\Outlook')
            )

            foreach ($directory in ($fallbackDirectories | Select-Object -Unique)) {
                if (-not (Test-Path -LiteralPath $directory -PathType Container -ErrorAction SilentlyContinue)) {
                    continue
                }

                foreach ($file in (Get-ChildItem -LiteralPath $directory -Filter '*.pst' -File -Recurse -Force -ErrorAction SilentlyContinue)) {
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
            $userName = Resolve-ProfileUserName -Sid $sid -ProfilePath $profilePath

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

    $accounts = @($accountResults.Values | Sort-Object sid, profileName, address, accountType)
    $pstFiles = foreach ($entry in ($pstCandidates.Values | Sort-Object sid, path)) {
        $fileInfo = Get-Item -LiteralPath $entry.path -ErrorAction SilentlyContinue
        $exists = $null -ne $fileInfo -and -not $fileInfo.PSIsContainer
        $upn = $accounts |
            Where-Object { $_.sid -eq $entry.sid } |
            Select-Object -First 1 -ExpandProperty address

        [pscustomobject]@{
            sid = $entry.sid
            userPrincipalName = $upn
            path = $entry.path
            sizeBytes = if ($exists) { [int64]$fileInfo.Length } else { [int64]0 }
            existsOnDisk = [bool]$exists
            lastWriteUtc = if ($exists) { $fileInfo.LastWriteTimeUtc.ToString('o') } else { $null }
        }
    }

    $legacyFiles = foreach ($entry in ($legacyCandidates.Values | Sort-Object sid, path)) {
        $upn = $accounts |
            Where-Object { $_.sid -eq $entry.sid } |
            Select-Object -First 1 -ExpandProperty address
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
            profileName = $entry.profileName
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

$started = Get-Date
$errors = @()

try { $device = Get-DeviceInfo } catch { $errors += "device: $($_.Exception.Message)"; $device = [pscustomobject]@{ hostname=$env:COMPUTERNAME; serialNumber=$null; os=$null; lastLoggedOnUser=$null; ips=@(); ou=$null; site=$null } }
try { $storage = Get-StorageInfo } catch { $errors += "storage: $($_.Exception.Message)"; $storage = [pscustomobject]@{ volumes=@(); disks=@() } }
try { $office = Get-OfficeInfo } catch { $errors += "office: $($_.Exception.Message)"; $office = [pscustomobject]@{ installedProducts=@(); runningProcesses=@() } }
try { $mail = Get-OutlookProfileInfo } catch { $errors += "outlook: $($_.Exception.Message)"; $mail = [pscustomobject]@{ profiles=@(); mailAccounts=@(); pstFiles=@(); legacyFiles=@() } }

$duration = [int]((Get-Date) - $started).TotalMilliseconds

$payload = [ordered]@{
    schemaVersion = '1.1'
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
