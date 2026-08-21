using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using System.Text;

namespace O365AuditTool.Services;

public interface IInventoryQueryService
{
    Task<List<DeviceInventory>> GetLatestDevicesAsync(string? ou, string? site, string? device, string? user, string? diskType, string? officeVersion, string? status, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken);
    Task<List<LicenseRecommendationDto>> GetLicenseRecommendationsAsync(CancellationToken cancellationToken);
    Task<byte[]> BuildDevicesCsvAsync(string? ou, string? site, string? device, string? user, string? diskType, string? officeVersion, string? status, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken);
    Task<byte[]> BuildExecutivePdfAsync(string? ou, string? site, string? device, string? user, string? diskType, string? officeVersion, string? status, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken);
}

public partial class InventoryQueryService(AuditDbContext db) : IInventoryQueryService
{
    public async Task<List<DeviceInventory>> GetLatestDevicesAsync(
        string? ou,
        string? site,
        string? device,
        string? user,
        string? diskType,
        string? officeVersion,
        string? status,
        long? pstMinBytes,
        long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var latestStates = await db.Devices
            .AsNoTracking()
            .GroupBy(x => x.DeviceName.ToUpper())
            .Select(group => group
                .OrderByDescending(x => x.CollectedUtc)
                .ThenByDescending(x => x.Id)
                .Select(x => new LatestDeviceState(
                    x.Id,
                    x.DeviceName,
                    x.Ou,
                    x.Site,
                    x.Status,
                    x.ErrorMessage,
                    x.PsExecExitCode,
                    x.CollectedUtc))
                .First())
            .ToListAsync(cancellationToken);

        DeviceScanStatus? parsedStatus = null;
        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!Enum.TryParse<DeviceScanStatus>(status.Trim(), ignoreCase: true, out var parsed))
            {
                return [];
            }
            parsedStatus = parsed;
        }

        IEnumerable<LatestDeviceState> filteredStates = latestStates;
        if (!string.IsNullOrWhiteSpace(ou))
        {
            filteredStates = filteredStates.Where(x =>
                x.Ou?.Contains(ou.Trim(), StringComparison.OrdinalIgnoreCase) == true);
        }
        if (!string.IsNullOrWhiteSpace(site))
        {
            filteredStates = filteredStates.Where(x =>
                string.Equals(x.Site?.Trim(), site.Trim(), StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrWhiteSpace(device))
        {
            filteredStates = filteredStates.Where(x =>
                x.DeviceName.Contains(device.Trim(), StringComparison.OrdinalIgnoreCase));
        }
        if (parsedStatus.HasValue)
        {
            filteredStates = filteredStates.Where(x => x.Status == parsedStatus.Value);
        }
        var scopedStates = filteredStates.ToList();

        var latestData = await db.Devices
            .AsNoTracking()
            .Where(x => x.RawPayloadJson != "{}")
            .GroupBy(x => x.DeviceName.ToUpper())
            .Select(group => group
                .OrderByDescending(x => x.CollectedUtc)
                .ThenByDescending(x => x.Id)
                .Select(x => new { Key = x.DeviceName.ToUpper(), x.Id })
                .First())
            .ToListAsync(cancellationToken);

        var latestDataByDevice = latestData.ToDictionary(x => x.Key, x => x.Id, StringComparer.OrdinalIgnoreCase);
        var selectedIds = scopedStates
            .Select(x => latestDataByDevice.GetValueOrDefault(x.DeviceName.ToUpperInvariant(), x.Id))
            .ToList();

        var query = db.Devices
            .AsNoTracking()
            .AsSplitQuery()
            .Include(x => x.Disks)
            .Include(x => x.Volumes)
            .Include(x => x.OfficeProducts)
            .Include(x => x.OfficeProcesses)
            .Include(x => x.Profiles)
            .Include(x => x.MailAccounts)
            .Include(x => x.PstFiles)
            .Include(x => x.LegacyFiles)
            .Where(x => selectedIds.Contains(x.Id));

        if (!string.IsNullOrWhiteSpace(user))
        {
            var value = user.Trim().ToUpperInvariant();
            query = query.Where(x =>
                x.MailAccounts.Any(m => m.Address != null && m.Address.ToUpper().Contains(value)) ||
                x.Profiles.Any(p => p.UserName != null && p.UserName.ToUpper().Contains(value)) ||
                (x.LastLoggedOnUser != null && x.LastLoggedOnUser.ToUpper().Contains(value)));
        }

        if (!string.IsNullOrWhiteSpace(diskType))
        {
            query = query.Where(x => x.Disks.Any(d =>
                (d.MediaType != null && d.MediaType == diskType) ||
                (d.BusType != null && d.BusType == diskType)));
        }

        if (!string.IsNullOrWhiteSpace(officeVersion))
        {
            query = query.Where(x => x.OfficeProducts.Any(p => p.Version != null && p.Version.Contains(officeVersion)));
        }

        var rows = await query.OrderBy(x => x.DeviceName).ToListAsync(cancellationToken);
        if (pstMinBytes.HasValue)
        {
            rows = rows
                .Where(x => GetPstTotalBytes(x) >= pstMinBytes.Value)
                .ToList();
        }

        if (pstMaxBytes.HasValue)
        {
            rows = rows
                .Where(x => GetPstTotalBytes(x) <= pstMaxBytes.Value)
                .ToList();
        }

        var stateByDevice = scopedStates.ToDictionary(x => x.DeviceName, StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            if (stateByDevice.TryGetValue(row.DeviceName, out var currentState))
            {
                row.Status = currentState.Status;
                row.ErrorMessage = currentState.ErrorMessage;
                row.PsExecExitCode = currentState.PsExecExitCode;
                row.Ou = currentState.Ou ?? row.Ou;
                row.Site = currentState.Site ?? row.Site;
            }
        }

        return rows;
    }

    private static long GetPstTotalBytes(DeviceInventory device)
    {
        try
        {
            return checked(device.PstFiles.Sum(x => x.SizeBytes));
        }
        catch (OverflowException)
        {
            return long.MaxValue;
        }
    }

    public async Task<List<LicenseRecommendationDto>> GetLicenseRecommendationsAsync(CancellationToken cancellationToken)
    {
        var devices = await GetLatestDevicesAsync(
            null, null, null, null, null, null, null, null, null, cancellationToken);
        var psts = devices.SelectMany(device => device.PstFiles.Select(pst => new PstLicenseInput(
            string.IsNullOrWhiteSpace(pst.UserPrincipalName) ? $"SID:{pst.Sid}" : pst.UserPrincipalName!,
            device.DeviceName,
            pst.Path,
            pst.SizeBytes,
            pst.ExistsOnDisk,
            device.Status == DeviceScanStatus.Success)));

        return LicenseRecommendationCalculator.Calculate(psts);
    }

    private sealed record LatestDeviceState(
        long Id,
        string DeviceName,
        string? Ou,
        string? Site,
        DeviceScanStatus Status,
        string? ErrorMessage,
        int? PsExecExitCode,
        DateTime CollectedUtc);
}

public sealed record PstLicenseInput(
    string UserKey,
    string DeviceName,
    string Path,
    long SizeBytes,
    bool ExistsOnDisk,
    bool IsReliable = true);

public static class LicenseRecommendationCalculator
{
    private const long GiB = 1024L * 1024 * 1024;

    public static List<LicenseRecommendationDto> Calculate(IEnumerable<PstLicenseInput> inputs)
    {
        var grouped = inputs.GroupBy(p => p.UserKey, StringComparer.OrdinalIgnoreCase);
        var result = new List<LicenseRecommendationDto>();

        foreach (var group in grouped)
        {
            var uniqueFiles = group
                .GroupBy(BuildFileIdentity, StringComparer.OrdinalIgnoreCase)
                .Select(files => files
                    .OrderByDescending(x => x.ExistsOnDisk)
                    .ThenByDescending(x => x.SizeBytes)
                    .First())
                .ToList();

            var total = uniqueFiles.Sum(x => x.SizeBytes);
            var recommendation = total switch
            {
                <= 50L * GiB => "Plan 1 capacity candidate",
                <= 100L * GiB => "Plan 2 capacity candidate",
                _ => "Archive/import strategy required"
            };

            var confidence = uniqueFiles.Count > 0 && uniqueFiles.All(x => x.ExistsOnDisk && x.IsReliable)
                ? "Medium"
                : "Low";
            result.Add(new LicenseRecommendationDto
            {
                UserKey = group.Key,
                TotalPstBytes = total,
                RecommendedLicense = recommendation,
                Confidence = confidence,
                AssessmentType = "PstCapacityHeuristic",
                RequiresTenantValidation = true,
                Caveat = "PST-only estimate. Validate current mailbox, archive usage, assigned SKU, retention, and import destination in Microsoft 365."
            });
        }

        return result.OrderByDescending(x => x.TotalPstBytes).ToList();
    }

    private static string BuildFileIdentity(PstLicenseInput input)
    {
        var normalizedPath = input.Path
            .Trim()
            .Trim('"')
            .Replace('/', '\\')
            .TrimEnd('\\');

        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return $"MISSING|{input.DeviceName}|{input.SizeBytes}";
        }

        return normalizedPath.StartsWith(@"\\", StringComparison.Ordinal)
            ? $"UNC|{normalizedPath}"
            : $"LOCAL|{input.DeviceName}|{normalizedPath}";
    }
}

public partial class InventoryQueryService
{
    public async Task<byte[]> BuildDevicesCsvAsync(
        string? ou,
        string? site,
        string? device,
        string? user,
        string? diskType,
        string? officeVersion,
        string? status,
        long? pstMinBytes,
        long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var rows = await GetLatestDevicesAsync(ou, site, device, user, diskType, officeVersion, status, pstMinBytes, pstMaxBytes, cancellationToken);
        var sb = new StringBuilder();
        sb.AppendLine("Device,OU,Site,OS,Serial,IPs,LastUser,CurrentUser,Profiles,MailAccounts,DiskTypes,Volumes,FreeSpaceGB,Office,RunningOffice,PstTotalGB,PstFiles,LegacyTotalGB,LegacyFiles,Status,DataCollectedUtc,ScanError");

        foreach (var row in rows)
        {
            var diskTypes = string.Join('|', row.Disks
                .SelectMany(x => new[] { x.MediaType, x.BusType })
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct());
            var freeSpace = row.Volumes.Sum(v => v.FreeBytes) / 1024d / 1024d / 1024d;
            var office = string.Join('|', row.OfficeProducts.Select(x =>
                $"{x.Name}:{x.Version}:type={x.InstallType}:arch={x.Architecture}:channel={x.UpdateChannel}:products={x.ProductIds}:updates={x.UpdatesEnabled}"));
            var running = string.Join('|', row.OfficeProcesses.Where(x => x.IsRunning).Select(x => $"{x.ProcessName}:{x.Pid}:{x.Owner}"));
            var ips = row.IpAddressesJson.Replace(',', '|').Replace("\"", string.Empty).Trim('[', ']');
            var pstGb = row.PstFiles.Sum(x => x.SizeBytes) / 1024d / 1024d / 1024d;
            var legacyGb = row.LegacyFiles.Sum(x => x.SizeBytes) / 1024d / 1024d / 1024d;
            var profiles = string.Join('|', row.Profiles.Select(x => $"{x.UserName}:{x.Sid}:{x.ProfileName}:loaded={x.Loaded}:default={x.IsDefault}:path={x.ProfilePath}"));
            var accounts = string.Join('|', row.MailAccounts.Select(x => $"{x.Address}:{x.AccountType}:{x.ProfileName}:{x.Sid}:active={x.IsActive}"));
            var volumes = string.Join('|', row.Volumes.Select(x => $"{x.Name}:total={x.TotalBytes}:free={x.FreeBytes}:{x.FileSystem}"));
            var psts = string.Join('|', row.PstFiles.Select(x => $"{x.UserPrincipalName}:{x.ProfileName}:{x.Path}:bytes={x.SizeBytes}:exists={x.ExistsOnDisk}:modified={x.LastWriteUtc:O}"));
            var legacyFiles = string.Join('|', row.LegacyFiles.Select(x => $"{x.UserPrincipalName}:{x.ProfileName}:{x.ArtifactType}:{x.Path}:bytes={x.SizeBytes}:exists={x.ExistsOnDisk}:modified={x.LastWriteUtc:O}"));

            sb.AppendLine(string.Join(',', new[]
            {
                Escape(row.DeviceName), Escape(row.Ou), Escape(row.Site), Escape(row.Os),
                Escape(row.SerialNumber), Escape(ips), Escape(row.LastLoggedOnUser), Escape(row.CurrentLoggedOnUser), Escape(profiles),
                Escape(accounts), Escape(diskTypes), Escape(volumes), freeSpace.ToString("F2", System.Globalization.CultureInfo.InvariantCulture),
                Escape(office), Escape(running), pstGb.ToString("F2", System.Globalization.CultureInfo.InvariantCulture),
                Escape(psts), legacyGb.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), Escape(legacyFiles),
                row.Status.ToString(), row.CollectedUtc.ToString("O"), Escape(row.ErrorMessage)
            }));
        }

        sb.Insert(0, '\uFEFF');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public async Task<byte[]> BuildExecutivePdfAsync(
        string? ou,
        string? site,
        string? device,
        string? user,
        string? diskType,
        string? officeVersion,
        string? status,
        long? pstMinBytes,
        long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var rows = await GetLatestDevicesAsync(ou, site, device, user, diskType, officeVersion, status, pstMinBytes, pstMaxBytes, cancellationToken);
        var recommendations = LicenseRecommendationCalculator.Calculate(
            rows.SelectMany(row => row.PstFiles.Select(pst => new PstLicenseInput(
                string.IsNullOrWhiteSpace(pst.UserPrincipalName) ? $"SID:{pst.Sid}" : pst.UserPrincipalName!,
                row.DeviceName,
                pst.Path,
                pst.SizeBytes,
                pst.ExistsOnDisk,
                row.Status == DeviceScanStatus.Success))));

        var totalDevices = rows.Count;
        var offline = rows.Count(x => x.Status == DeviceScanStatus.Offline);
        var partialOrError = rows.Count(x => x.Status is DeviceScanStatus.Error or DeviceScanStatus.Partial or DeviceScanStatus.Timeout);
        var totalPstGb = recommendations.Sum(x => x.TotalPstBytes) / 1024d / 1024d / 1024d;
        var legacyCount = rows.Sum(x => x.LegacyFiles.Count);
        var legacyGb = rows.Sum(x => x.LegacyFiles.Sum(file => file.SizeBytes)) / 1024d / 1024d / 1024d;
        var lowConfidence = recommendations.Count(x => x.Confidence == "Low");
        var topUsers = string.Join("; ", recommendations.Take(5).Select(x => $"{x.UserKey}:{x.TotalPstBytes / 1024d / 1024d / 1024d:F1}GB"));

        var lines = new[]
        {
            "Executive Migration Audit Summary",
            $"Generated UTC: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}",
            $"Devices inventoried: {totalDevices}",
            $"Offline devices: {offline}",
            $"Partial/error devices: {partialOrError}",
            $"Deduplicated PST volume: {totalPstGb:F2} GB",
            $"NK2/N2K artifacts: {legacyCount} ({legacyGb:F2} GB)",
            $"Low confidence PST capacity assessments: {lowConfidence}",
            "Top PST owners:",
            topUsers
        };

        return MinimalPdfBuilder.BuildSinglePage(lines);
    }

    private static string Escape(string? value)
    {
        var raw = value ?? string.Empty;
        if (raw.Length > 0 && raw[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n')
        {
            raw = $"'{raw}";
        }

        var cleaned = raw.Replace("\"", "\"\"");
        return $"\"{cleaned}\"";
    }
}

public static class MinimalPdfBuilder
{
    public static byte[] BuildSinglePage(IEnumerable<string> lines)
    {
        var textCommands = lines
            .Select(EscapePdfText)
            .Select((line, index) => index == 0 ? $"({line}) Tj" : $"T* ({line}) Tj");
        var content = $"BT /F1 12 Tf 50 780 Td 15 TL {string.Join(' ', textCommands)} ET";
        var contentLength = Encoding.ASCII.GetByteCount(content);

        var objects = new List<string>
        {
            "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
            "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
            "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
            $"4 0 obj << /Length {contentLength} >> stream\n{content}\nendstream endobj",
            "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj"
        };

        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.4");
        var offsets = new List<int>();
        foreach (var obj in objects)
        {
            offsets.Add(Encoding.ASCII.GetByteCount(sb.ToString()));
            sb.AppendLine(obj);
        }

        var xrefStart = Encoding.ASCII.GetByteCount(sb.ToString());
        sb.AppendLine("xref");
        sb.AppendLine($"0 {objects.Count + 1}");
        sb.AppendLine("0000000000 65535 f ");
        foreach (var offset in offsets)
        {
            sb.AppendLine($"{offset:D10} 00000 n ");
        }

        sb.AppendLine("trailer");
        sb.AppendLine($"<< /Size {objects.Count + 1} /Root 1 0 R >>");
        sb.AppendLine("startxref");
        sb.AppendLine(xrefStart.ToString());
        sb.AppendLine("%%EOF");

        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static string EscapePdfText(string input) => input.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
}
