using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using System.Text;

namespace O365AuditTool.Services;

public interface IInventoryQueryService
{
    Task<List<DeviceInventory>> GetLatestDevicesAsync(string? device, string? user, string? diskType, string? officeVersion, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken);
    Task<List<LicenseRecommendationDto>> GetLicenseRecommendationsAsync(CancellationToken cancellationToken);
    Task<byte[]> BuildDevicesCsvAsync(string? device, string? user, string? diskType, string? officeVersion, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken);
    Task<byte[]> BuildExecutivePdfAsync(string? device, string? user, string? diskType, string? officeVersion, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken);
}

public partial class InventoryQueryService(AuditDbContext db) : IInventoryQueryService
{
    public async Task<List<DeviceInventory>> GetLatestDevicesAsync(string? device, string? user, string? diskType, string? officeVersion, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken)
    {
        var latestIds = await db.Devices
            .GroupBy(x => x.DeviceName)
            .Select(g => g.OrderByDescending(d => d.CollectedUtc).Select(d => d.Id).First())
            .ToListAsync(cancellationToken);

        var query = db.Devices
            .AsNoTracking()
            .Include(x => x.Disks)
            .Include(x => x.Volumes)
            .Include(x => x.OfficeProducts)
            .Include(x => x.OfficeProcesses)
            .Include(x => x.MailAccounts)
            .Include(x => x.PstFiles)
            .Where(x => latestIds.Contains(x.Id));

        if (!string.IsNullOrWhiteSpace(device))
        {
            query = query.Where(x => x.DeviceName.Contains(device));
        }

        if (!string.IsNullOrWhiteSpace(user))
        {
            query = query.Where(x => x.MailAccounts.Any(m => m.Address != null && m.Address.Contains(user)) || (x.LastLoggedOnUser != null && x.LastLoggedOnUser.Contains(user)));
        }

        if (!string.IsNullOrWhiteSpace(diskType))
        {
            query = query.Where(x => x.Disks.Any(d => d.MediaType != null && d.MediaType == diskType));
        }

        if (!string.IsNullOrWhiteSpace(officeVersion))
        {
            query = query.Where(x => x.OfficeProducts.Any(p => p.Version != null && p.Version.Contains(officeVersion)));
        }

        if (pstMinBytes.HasValue)
        {
            query = query.Where(x => x.PstFiles.Sum(p => p.SizeBytes) >= pstMinBytes.Value);
        }

        if (pstMaxBytes.HasValue)
        {
            query = query.Where(x => x.PstFiles.Sum(p => p.SizeBytes) <= pstMaxBytes.Value);
        }

        return await query.OrderBy(x => x.DeviceName).ToListAsync(cancellationToken);
    }

    public async Task<List<LicenseRecommendationDto>> GetLicenseRecommendationsAsync(CancellationToken cancellationToken)
    {
        var latestIds = await db.Devices
            .GroupBy(x => x.DeviceName)
            .Select(g => g.OrderByDescending(d => d.CollectedUtc).Select(d => d.Id).First())
            .ToListAsync(cancellationToken);

        var psts = await (
                from pst in db.PstFiles.AsNoTracking()
                join device in db.Devices.AsNoTracking() on pst.DeviceInventoryId equals device.Id
                where latestIds.Contains(pst.DeviceInventoryId)
                select new PstLicenseInput(
                    string.IsNullOrWhiteSpace(pst.UserPrincipalName) ? $"SID:{pst.Sid}" : pst.UserPrincipalName!,
                    device.DeviceName,
                    pst.Path,
                    pst.SizeBytes,
                    pst.ExistsOnDisk))
            .ToListAsync(cancellationToken);

        return LicenseRecommendationCalculator.Calculate(psts);
    }
}

public sealed record PstLicenseInput(
    string UserKey,
    string DeviceName,
    string Path,
    long SizeBytes,
    bool ExistsOnDisk);

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
                <= 50L * GiB => "Exchange Online Plan 1",
                <= 100L * GiB => "Exchange Online Plan 2",
                _ => "Exchange Online Plan 2 + Online Archive"
            };

            var confidence = uniqueFiles.Count > 0 && uniqueFiles.All(x => x.ExistsOnDisk) ? "High" : "Low";
            result.Add(new LicenseRecommendationDto
            {
                UserKey = group.Key,
                TotalPstBytes = total,
                RecommendedLicense = recommendation,
                Confidence = confidence
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
    public async Task<byte[]> BuildDevicesCsvAsync(string? device, string? user, string? diskType, string? officeVersion, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken)
    {
        var rows = await GetLatestDevicesAsync(device, user, diskType, officeVersion, pstMinBytes, pstMaxBytes, cancellationToken);
        var sb = new StringBuilder();
        sb.AppendLine("Device,OS,Serial,IPs,LastUser,DiskTypes,FreeSpaceGB,Office,RunningOffice,PstTotalGB,Status,CollectedUtc");

        foreach (var row in rows)
        {
            var diskTypes = string.Join('|', row.Disks.Select(x => x.MediaType).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct());
            var freeSpace = row.Volumes.Sum(v => v.FreeBytes) / 1024d / 1024d / 1024d;
            var office = string.Join('|', row.OfficeProducts.Select(x => $"{x.Name} {x.Version}"));
            var running = string.Join('|', row.OfficeProcesses.Where(x => x.IsRunning).Select(x => x.ProcessName));
            var ips = row.IpAddressesJson.Replace(',', '|').Replace("\"", string.Empty).Trim('[', ']');
            var pstGb = row.PstFiles.Sum(x => x.SizeBytes) / 1024d / 1024d / 1024d;

            sb.AppendLine($"{Escape(row.DeviceName)},{Escape(row.Os)},{Escape(row.SerialNumber)},{Escape(ips)},{Escape(row.LastLoggedOnUser)},{Escape(diskTypes)},{freeSpace:F2},{Escape(office)},{Escape(running)},{pstGb:F2},{row.Status},{row.CollectedUtc:O}");
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public async Task<byte[]> BuildExecutivePdfAsync(string? device, string? user, string? diskType, string? officeVersion, long? pstMinBytes, long? pstMaxBytes, CancellationToken cancellationToken)
    {
        var rows = await GetLatestDevicesAsync(device, user, diskType, officeVersion, pstMinBytes, pstMaxBytes, cancellationToken);
        var recommendations = LicenseRecommendationCalculator.Calculate(
            rows.SelectMany(row => row.PstFiles.Select(pst => new PstLicenseInput(
                string.IsNullOrWhiteSpace(pst.UserPrincipalName) ? $"SID:{pst.Sid}" : pst.UserPrincipalName!,
                row.DeviceName,
                pst.Path,
                pst.SizeBytes,
                pst.ExistsOnDisk))));

        var totalDevices = rows.Count;
        var offline = rows.Count(x => x.Status == DeviceScanStatus.Offline);
        var totalPstGb = rows.Sum(x => x.PstFiles.Sum(p => p.SizeBytes)) / 1024d / 1024d / 1024d;
        var topUsers = string.Join("; ", recommendations.Take(5).Select(x => $"{x.UserKey}:{x.TotalPstBytes / 1024d / 1024d / 1024d:F1}GB"));

        var lines = new[]
        {
            "Executive Migration Audit Summary",
            $"Generated UTC: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}",
            $"Devices inventoried: {totalDevices}",
            $"Offline devices: {offline}",
            $"Total PST volume: {totalPstGb:F2} GB",
            "Top PST owners:",
            topUsers
        };

        return MinimalPdfBuilder.BuildSinglePage(lines);
    }

    private static string Escape(string? value)
    {
        var cleaned = (value ?? string.Empty).Replace("\"", "\"\"");
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

