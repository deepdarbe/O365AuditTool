using System.ComponentModel.DataAnnotations;

namespace O365AuditTool.Models;

public enum JobStatus
{
    Queued,
    Running,
    Completed,
    CompletedWithErrors,
    Failed
}

public enum DeviceScanStatus
{
    Success,
    Offline,
    Error,
    Partial,
    Timeout
}

public enum CopyJobStatus
{
    Planned,
    Queued,
    Running,
    Completed,
    CompletedWithErrors,
    Failed
}

public enum CopyItemStatus
{
    Planned,
    Queued,
    Copying,
    Completed,
    Skipped,
    Failed
}

public class ScanJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [MaxLength(128)] public string RequestedBy { get; set; } = "system";
    [MaxLength(256)] public string? OuFilter { get; set; }
    [MaxLength(256)] public string? SiteFilter { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public JobStatus Status { get; set; } = JobStatus.Queued;
    [MaxLength(1024)] public string? Notes { get; set; }
    public ICollection<DeviceInventory> Devices { get; set; } = new List<DeviceInventory>();
}

public class RetryQueueItem
{
    public long Id { get; set; }
    [MaxLength(64)] public string DeviceName { get; set; } = string.Empty;
    [MaxLength(256)] public string? Ou { get; set; }
    [MaxLength(64)] public string? Site { get; set; }
    public Guid ScanJobId { get; set; }
    public int Attempt { get; set; }
    public DateTime NextAttemptUtc { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public class DeviceInventory
{
    public long Id { get; set; }
    public Guid ScanJobId { get; set; }
    [MaxLength(64)] public string DeviceName { get; set; } = string.Empty;
    [MaxLength(128)] public string? SerialNumber { get; set; }
    [MaxLength(128)] public string? Os { get; set; }
    [MaxLength(128)] public string? LastLoggedOnUser { get; set; }
    [MaxLength(128)] public string? CurrentLoggedOnUser { get; set; }
    [MaxLength(256)] public string? Ou { get; set; }
    [MaxLength(64)] public string? Site { get; set; }
    public DateTime CollectedUtc { get; set; }
    public DeviceScanStatus Status { get; set; } = DeviceScanStatus.Success;
    [MaxLength(4096)] public string? ErrorMessage { get; set; }
    public string IpAddressesJson { get; set; } = "[]";
    public string RawPayloadJson { get; set; } = "{}";

    public ICollection<StorageVolume> Volumes { get; set; } = new List<StorageVolume>();
    public ICollection<DiskInfo> Disks { get; set; } = new List<DiskInfo>();
    public ICollection<OfficeProduct> OfficeProducts { get; set; } = new List<OfficeProduct>();
    public ICollection<OfficeProcess> OfficeProcesses { get; set; } = new List<OfficeProcess>();
    public ICollection<MailProfile> Profiles { get; set; } = new List<MailProfile>();
    public ICollection<MailAccount> MailAccounts { get; set; } = new List<MailAccount>();
    public ICollection<PstFileRecord> PstFiles { get; set; } = new List<PstFileRecord>();
    public ICollection<LegacyMailFileRecord> LegacyFiles { get; set; } = new List<LegacyMailFileRecord>();
}

public class StorageVolume
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(16)] public string Name { get; set; } = string.Empty;
    public long TotalBytes { get; set; }
    public long FreeBytes { get; set; }
    [MaxLength(32)] public string? FileSystem { get; set; }
}

public class DiskInfo
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(256)] public string? Model { get; set; }
    [MaxLength(32)] public string? InterfaceType { get; set; }
    [MaxLength(32)] public string? BusType { get; set; }
    [MaxLength(32)] public string? MediaType { get; set; }
    public long SizeBytes { get; set; }
}

public class OfficeProduct
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(256)] public string Name { get; set; } = string.Empty;
    [MaxLength(64)] public string? Version { get; set; }
    [MaxLength(64)] public string? InstallType { get; set; }
    [MaxLength(32)] public string? Architecture { get; set; }
    [MaxLength(128)] public string? UpdateChannel { get; set; }
    [MaxLength(512)] public string? ProductIds { get; set; }
    public bool? UpdatesEnabled { get; set; }
}

public class OfficeProcess
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(32)] public string ProcessName { get; set; } = string.Empty;
    public int? Pid { get; set; }
    public DateTime? StartTimeUtc { get; set; }
    public bool IsRunning { get; set; }
    [MaxLength(256)] public string? Owner { get; set; }
    public int? SessionId { get; set; }
}

public class MailProfile
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(128)] public string Sid { get; set; } = string.Empty;
    [MaxLength(256)] public string ProfileName { get; set; } = string.Empty;
    [MaxLength(1024)] public string? ProfilePath { get; set; }
    [MaxLength(256)] public string? UserName { get; set; }
    public bool Loaded { get; set; }
    public bool IsDefault { get; set; }
}

public class MailAccount
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(128)] public string Sid { get; set; } = string.Empty;
    [MaxLength(256)] public string? ProfileName { get; set; }
    [MaxLength(64)] public string AccountType { get; set; } = "Unknown";
    [MaxLength(320)] public string? Address { get; set; }
    public bool IsActive { get; set; }
}

public class PstFileRecord
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(128)] public string Sid { get; set; } = string.Empty;
    [MaxLength(320)] public string? UserPrincipalName { get; set; }
    [MaxLength(256)] public string? ProfileName { get; set; }
    [MaxLength(1024)] public string Path { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public bool ExistsOnDisk { get; set; }
    public DateTime? LastWriteUtc { get; set; }
}

public class LegacyMailFileRecord
{
    public long Id { get; set; }
    public long DeviceInventoryId { get; set; }
    [MaxLength(128)] public string Sid { get; set; } = string.Empty;
    [MaxLength(256)] public string? UserName { get; set; }
    [MaxLength(320)] public string? UserPrincipalName { get; set; }
    [MaxLength(256)] public string? ProfileName { get; set; }
    [MaxLength(16)] public string ArtifactType { get; set; } = "NK2";
    [MaxLength(1024)] public string Path { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public bool ExistsOnDisk { get; set; }
    public DateTime? LastWriteUtc { get; set; }
}

public class ArtifactCopyJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [MaxLength(128)] public string RequestedBy { get; set; } = "system";
    [MaxLength(128)] public string? ExecutedBy { get; set; }
    [MaxLength(1024)] public string TargetRoot { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? QueuedUtc { get; set; }
    public DateTime? StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public CopyJobStatus Status { get; set; } = CopyJobStatus.Planned;
    [MaxLength(2048)] public string? Notes { get; set; }
    public ICollection<ArtifactCopyItem> Items { get; set; } = new List<ArtifactCopyItem>();
}

public class ArtifactCopyItem
{
    public long Id { get; set; }
    public Guid ArtifactCopyJobId { get; set; }
    [MaxLength(64)] public string DeviceName { get; set; } = string.Empty;
    [MaxLength(320)] public string UserKey { get; set; } = string.Empty;
    [MaxLength(256)] public string? ProfileName { get; set; }
    [MaxLength(16)] public string ArtifactType { get; set; } = string.Empty;
    [MaxLength(1024)] public string SourcePath { get; set; } = string.Empty;
    public long SourceSizeBytes { get; set; }
    public DateTime? SourceLastWriteUtc { get; set; }
    [MaxLength(2048)] public string DestinationPath { get; set; } = string.Empty;
    public CopyItemStatus Status { get; set; } = CopyItemStatus.Planned;
    public int Attempts { get; set; }
    [MaxLength(4096)] public string? ErrorMessage { get; set; }
    public DateTime? CopiedUtc { get; set; }
    public long? DestinationSizeBytes { get; set; }
    [MaxLength(64)] public string? Sha256 { get; set; }
}
