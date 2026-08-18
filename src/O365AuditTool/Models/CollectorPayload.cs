using System.Text.Json.Serialization;

namespace O365AuditTool.Models;

public class CollectorPayload
{
    [JsonPropertyName("schemaVersion")] public string SchemaVersion { get; set; } = "1.3";
    [JsonPropertyName("device")] public CollectorDevice Device { get; set; } = new();
    [JsonPropertyName("storage")] public CollectorStorage Storage { get; set; } = new();
    [JsonPropertyName("office")] public CollectorOffice Office { get; set; } = new();
    [JsonPropertyName("profiles")] public List<CollectorProfile> Profiles { get; set; } = new();
    [JsonPropertyName("mailAccounts")] public List<CollectorMailAccount> MailAccounts { get; set; } = new();
    [JsonPropertyName("pstFiles")] public List<CollectorPstFile> PstFiles { get; set; } = new();
    [JsonPropertyName("legacyFiles")] public List<CollectorLegacyFile> LegacyFiles { get; set; } = new();
    [JsonPropertyName("scanMeta")] public CollectorScanMeta ScanMeta { get; set; } = new();
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = new();
}

public class CollectorDevice
{
    [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
    [JsonPropertyName("serialNumber")] public string? SerialNumber { get; set; }
    [JsonPropertyName("os")] public string? Os { get; set; }
    [JsonPropertyName("lastLoggedOnUser")] public string? LastLoggedOnUser { get; set; }
    [JsonPropertyName("currentLoggedOnUser")] public string? CurrentLoggedOnUser { get; set; }
    [JsonPropertyName("ips")] public List<string> Ips { get; set; } = new();
    [JsonPropertyName("ou")] public string? Ou { get; set; }
    [JsonPropertyName("site")] public string? Site { get; set; }
}

public class CollectorStorage
{
    [JsonPropertyName("volumes")] public List<CollectorVolume> Volumes { get; set; } = new();
    [JsonPropertyName("disks")] public List<CollectorDisk> Disks { get; set; } = new();
}

public class CollectorVolume
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("totalBytes")] public long TotalBytes { get; set; }
    [JsonPropertyName("freeBytes")] public long FreeBytes { get; set; }
    [JsonPropertyName("fileSystem")] public string? FileSystem { get; set; }
}

public class CollectorDisk
{
    [JsonPropertyName("model")] public string? Model { get; set; }
    [JsonPropertyName("interfaceType")] public string? InterfaceType { get; set; }
    [JsonPropertyName("busType")] public string? BusType { get; set; }
    [JsonPropertyName("mediaType")] public string? MediaType { get; set; }
    [JsonPropertyName("sizeBytes")] public long SizeBytes { get; set; }
}

public class CollectorOffice
{
    [JsonPropertyName("installedProducts")] public List<CollectorOfficeProduct> InstalledProducts { get; set; } = new();
    [JsonPropertyName("runningProcesses")] public List<CollectorOfficeProcess> RunningProcesses { get; set; } = new();
}

public class CollectorOfficeProduct
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("installType")] public string? InstallType { get; set; }
    [JsonPropertyName("architecture")] public string? Architecture { get; set; }
    [JsonPropertyName("updateChannel")] public string? UpdateChannel { get; set; }
    [JsonPropertyName("productIds")] public string? ProductIds { get; set; }
    [JsonPropertyName("updatesEnabled")] public bool? UpdatesEnabled { get; set; }
}

public class CollectorOfficeProcess
{
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = string.Empty;
    [JsonPropertyName("pid")] public int? Pid { get; set; }
    [JsonPropertyName("startTimeUtc")] public DateTime? StartTimeUtc { get; set; }
    [JsonPropertyName("isRunning")] public bool IsRunning { get; set; }
    [JsonPropertyName("owner")] public string? Owner { get; set; }
    [JsonPropertyName("sessionId")] public int? SessionId { get; set; }
}

public class CollectorProfile
{
    [JsonPropertyName("sid")] public string Sid { get; set; } = string.Empty;
    [JsonPropertyName("profileName")] public string ProfileName { get; set; } = string.Empty;
    [JsonPropertyName("profilePath")] public string? ProfilePath { get; set; }
    [JsonPropertyName("userName")] public string? UserName { get; set; }
    [JsonPropertyName("loaded")] public bool Loaded { get; set; }
    [JsonPropertyName("isDefault")] public bool IsDefault { get; set; }
}

public class CollectorMailAccount
{
    [JsonPropertyName("sid")] public string Sid { get; set; } = string.Empty;
    [JsonPropertyName("profileName")] public string? ProfileName { get; set; }
    [JsonPropertyName("accountType")] public string AccountType { get; set; } = "Unknown";
    [JsonPropertyName("address")] public string? Address { get; set; }
    [JsonPropertyName("isActive")] public bool IsActive { get; set; }
}

public class CollectorPstFile
{
    [JsonPropertyName("sid")] public string Sid { get; set; } = string.Empty;
    [JsonPropertyName("userPrincipalName")] public string? UserPrincipalName { get; set; }
    [JsonPropertyName("profileName")] public string? ProfileName { get; set; }
    [JsonPropertyName("path")] public string Path { get; set; } = string.Empty;
    [JsonPropertyName("sizeBytes")] public long SizeBytes { get; set; }
    [JsonPropertyName("existsOnDisk")] public bool ExistsOnDisk { get; set; }
    [JsonPropertyName("lastWriteUtc")] public DateTime? LastWriteUtc { get; set; }
}

public class CollectorLegacyFile
{
    [JsonPropertyName("sid")] public string Sid { get; set; } = string.Empty;
    [JsonPropertyName("userName")] public string? UserName { get; set; }
    [JsonPropertyName("userPrincipalName")] public string? UserPrincipalName { get; set; }
    [JsonPropertyName("profileName")] public string? ProfileName { get; set; }
    [JsonPropertyName("artifactType")] public string ArtifactType { get; set; } = "NK2";
    [JsonPropertyName("path")] public string Path { get; set; } = string.Empty;
    [JsonPropertyName("sizeBytes")] public long SizeBytes { get; set; }
    [JsonPropertyName("existsOnDisk")] public bool ExistsOnDisk { get; set; }
    [JsonPropertyName("lastWriteUtc")] public DateTime? LastWriteUtc { get; set; }
}

public class CollectorScanMeta
{
    [JsonPropertyName("scanTimestampUtc")] public DateTime ScanTimestampUtc { get; set; } = DateTime.UtcNow;
    [JsonPropertyName("durationMs")] public int DurationMs { get; set; }
}

public record StartScanRequest(string? OuFilter, string? SiteFilter, bool Manual = true);

public record CreateCopyPlanRequest(
    string? TargetRoot,
    string[]? Devices,
    string[]? Users,
    string[]? ArtifactTypes);

public class LicenseRecommendationDto
{
    public string UserKey { get; set; } = string.Empty;
    public long TotalPstBytes { get; set; }
    public string RecommendedLicense { get; set; } = string.Empty;
    public string Confidence { get; set; } = "Medium";
    public string AssessmentType { get; set; } = "PstCapacityHeuristic";
    public bool RequiresTenantValidation { get; set; } = true;
    public string Caveat { get; set; } = string.Empty;
}
