using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;

namespace O365AuditTool.Services;

public interface IInventoryIngestionService
{
    Task<DeviceInventory> SavePayloadAsync(Guid jobId, DeviceTarget target, CollectorPayload payload, CancellationToken cancellationToken);
    Task<DeviceInventory> SaveFailureAsync(Guid jobId, DeviceTarget target, string error, DeviceScanStatus status, CancellationToken cancellationToken);
}

public class InventoryIngestionService(AuditDbContext dbContext) : IInventoryIngestionService
{
    public async Task<DeviceInventory> SavePayloadAsync(Guid jobId, DeviceTarget target, CollectorPayload payload, CancellationToken cancellationToken)
    {
        var device = new DeviceInventory
        {
            ScanJobId = jobId,
            DeviceName = payload.Device.Hostname,
            SerialNumber = payload.Device.SerialNumber,
            Os = payload.Device.Os,
            LastLoggedOnUser = payload.Device.LastLoggedOnUser,
            CurrentLoggedOnUser = payload.Device.CurrentLoggedOnUser,
            Ou = payload.Device.Ou ?? target.Ou,
            Site = payload.Device.Site ?? target.Site,
            CollectedUtc = payload.ScanMeta.ScanTimestampUtc == default ? DateTime.UtcNow : payload.ScanMeta.ScanTimestampUtc,
            Status = payload.Errors.Count == 0 ? DeviceScanStatus.Success : DeviceScanStatus.Partial,
            ErrorMessage = payload.Errors.Count == 0 ? null : string.Join(" | ", payload.Errors),
            IpAddressesJson = JsonSerializer.Serialize(payload.Device.Ips),
            RawPayloadJson = JsonSerializer.Serialize(payload)
        };

        foreach (var volume in payload.Storage.Volumes)
        {
            device.Volumes.Add(new StorageVolume
            {
                Name = volume.Name,
                TotalBytes = volume.TotalBytes,
                FreeBytes = volume.FreeBytes,
                FileSystem = volume.FileSystem
            });
        }

        foreach (var disk in payload.Storage.Disks)
        {
            device.Disks.Add(new DiskInfo
            {
                Model = disk.Model,
                InterfaceType = disk.InterfaceType,
                BusType = disk.BusType,
                MediaType = disk.MediaType,
                SizeBytes = disk.SizeBytes
            });
        }

        foreach (var product in payload.Office.InstalledProducts)
        {
            device.OfficeProducts.Add(new OfficeProduct
            {
                Name = product.Name,
                Version = product.Version,
                InstallType = product.InstallType,
                Architecture = product.Architecture,
                UpdateChannel = product.UpdateChannel,
                ProductIds = product.ProductIds,
                UpdatesEnabled = product.UpdatesEnabled
            });
        }

        foreach (var proc in payload.Office.RunningProcesses)
        {
            device.OfficeProcesses.Add(new OfficeProcess
            {
                ProcessName = proc.ProcessName,
                Pid = proc.Pid,
                StartTimeUtc = proc.StartTimeUtc,
                IsRunning = proc.IsRunning,
                Owner = proc.Owner,
                SessionId = proc.SessionId
            });
        }

        foreach (var profile in payload.Profiles)
        {
            device.Profiles.Add(new MailProfile
            {
                Sid = profile.Sid,
                ProfileName = profile.ProfileName,
                ProfilePath = profile.ProfilePath,
                UserName = profile.UserName,
                Loaded = profile.Loaded,
                IsDefault = profile.IsDefault
            });
        }

        foreach (var account in payload.MailAccounts)
        {
            device.MailAccounts.Add(new MailAccount
            {
                Sid = account.Sid,
                ProfileName = account.ProfileName,
                AccountType = account.AccountType,
                Address = account.Address,
                IsActive = account.IsActive
            });
        }

        foreach (var pst in payload.PstFiles)
        {
            device.PstFiles.Add(new PstFileRecord
            {
                Sid = pst.Sid,
                UserPrincipalName = pst.UserPrincipalName,
                ProfileName = pst.ProfileName,
                Path = pst.Path,
                SizeBytes = pst.SizeBytes,
                ExistsOnDisk = pst.ExistsOnDisk,
                LastWriteUtc = pst.LastWriteUtc
            });
        }

        var legacyFileKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var legacyFile in payload.LegacyFiles)
        {
            var path = legacyFile.Path?.Trim();
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            var artifactType = legacyFile.ArtifactType?.Trim().ToUpperInvariant();
            if (artifactType is not ("NK2" or "N2K"))
            {
                continue;
            }

            var sid = legacyFile.Sid?.Trim() ?? string.Empty;
            if (!legacyFileKeys.Add($"{sid}\u001F{path}"))
            {
                continue;
            }

            device.LegacyFiles.Add(new LegacyMailFileRecord
            {
                Sid = sid,
                UserName = legacyFile.UserName,
                UserPrincipalName = legacyFile.UserPrincipalName,
                ProfileName = legacyFile.ProfileName,
                ArtifactType = artifactType,
                Path = path,
                SizeBytes = legacyFile.SizeBytes,
                ExistsOnDisk = legacyFile.ExistsOnDisk,
                LastWriteUtc = legacyFile.LastWriteUtc
            });
        }

        await RemovePreviousAttemptAsync(jobId, target.Name, cancellationToken);
        dbContext.Devices.Add(device);
        await dbContext.SaveChangesAsync(cancellationToken);
        return device;
    }

    public async Task<DeviceInventory> SaveFailureAsync(Guid jobId, DeviceTarget target, string error, DeviceScanStatus status, CancellationToken cancellationToken)
    {
        if (status is DeviceScanStatus.Success or DeviceScanStatus.Partial)
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "Failure records require Offline, Timeout, or Error status.");
        }

        var device = new DeviceInventory
        {
            ScanJobId = jobId,
            DeviceName = target.Name,
            Ou = target.Ou,
            Site = target.Site,
            CollectedUtc = DateTime.UtcNow,
            Status = status,
            ErrorMessage = Truncate(error, 4096),
            IpAddressesJson = "[]",
            RawPayloadJson = "{}"
        };

        await RemovePreviousAttemptAsync(jobId, target.Name, cancellationToken);
        dbContext.Devices.Add(device);
        await dbContext.SaveChangesAsync(cancellationToken);
        return device;
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private Task RemovePreviousAttemptAsync(Guid jobId, string deviceName, CancellationToken cancellationToken) =>
        dbContext.Devices
            .Where(x => x.ScanJobId == jobId && x.DeviceName.ToUpper() == deviceName.Trim().ToUpper())
            .ExecuteDeleteAsync(cancellationToken);
}
