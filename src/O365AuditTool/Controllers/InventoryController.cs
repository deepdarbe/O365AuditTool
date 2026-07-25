using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/inventory")]
[Authorize(Policy = "AuditReader")]
public class InventoryController(IInventoryQueryService queryService, AuditDbContext dbContext) : ControllerBase
{
    [HttpGet("devices")]
    public async Task<IActionResult> GetDevices(
        [FromQuery] string? device,
        [FromQuery] string? user,
        [FromQuery] string? diskType,
        [FromQuery] string? officeVersion,
        [FromQuery] long? pstMinBytes,
        [FromQuery] long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var devices = await queryService.GetLatestDevicesAsync(device, user, diskType, officeVersion, pstMinBytes, pstMaxBytes, cancellationToken);
        return Ok(devices.Select(d => new
        {
            d.Id,
            d.DeviceName,
            d.SerialNumber,
            d.Os,
            d.LastLoggedOnUser,
            d.Ou,
            d.Site,
            d.CollectedUtc,
            d.Status,
            ipAddresses = d.IpAddressesJson,
            pstTotalBytes = d.PstFiles.Sum(x => x.SizeBytes),
            disks = d.Disks.Select(x => new { x.Model, x.InterfaceType, x.MediaType, x.SizeBytes }),
            volumes = d.Volumes.Select(x => new { x.Name, x.TotalBytes, x.FreeBytes, x.FileSystem }),
            officeProducts = d.OfficeProducts.Select(x => new { x.Name, x.Version, x.InstallType }),
            officeProcesses = d.OfficeProcesses.Select(x => new { x.ProcessName, x.IsRunning, x.Pid, x.StartTimeUtc }),
            mailAccounts = d.MailAccounts.Select(x => new { x.Sid, x.ProfileName, x.AccountType, x.Address }),
            pstFiles = d.PstFiles.Select(x => new { x.Sid, x.UserPrincipalName, x.Path, x.SizeBytes, x.ExistsOnDisk, x.LastWriteUtc })
        }));
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers(CancellationToken cancellationToken)
    {
        var recs = await queryService.GetLicenseRecommendationsAsync(cancellationToken);
        return Ok(recs.Select(x => new
        {
            user = x.UserKey,
            totalPstBytes = x.TotalPstBytes,
            recommendedLicense = x.RecommendedLicense,
            confidence = x.Confidence
        }));
    }

    [HttpGet("legacy-files")]
    public async Task<IActionResult> GetLegacyFiles(
        [FromQuery] string? device,
        [FromQuery] string? user,
        [FromQuery] string? profile,
        [FromQuery] string? artifactType,
        CancellationToken cancellationToken)
    {
        var latestSnapshotIds = dbContext.Devices
            .AsNoTracking()
            .GroupBy(x => x.DeviceName)
            .Select(group => group
                .OrderByDescending(x => x.CollectedUtc)
                .ThenByDescending(x => x.Id)
                .Select(x => x.Id)
                .First());

        var query =
            from legacyFile in dbContext.LegacyFiles.AsNoTracking()
            join snapshot in dbContext.Devices.AsNoTracking()
                on legacyFile.DeviceInventoryId equals snapshot.Id
            where latestSnapshotIds.Contains(snapshot.Id)
            select new
            {
                snapshot.DeviceName,
                snapshot.CollectedUtc,
                snapshot.Status,
                snapshot.ErrorMessage,
                legacyFile.UserName,
                legacyFile.Sid,
                legacyFile.UserPrincipalName,
                legacyFile.ProfileName,
                legacyFile.ArtifactType,
                legacyFile.Path,
                legacyFile.SizeBytes,
                legacyFile.ExistsOnDisk,
                legacyFile.LastWriteUtc
            };

        if (!string.IsNullOrWhiteSpace(device))
        {
            var deviceFilter = device.Trim().ToUpperInvariant();
            query = query.Where(x => x.DeviceName.ToUpper().Contains(deviceFilter));
        }

        if (!string.IsNullOrWhiteSpace(user))
        {
            var userFilter = user.Trim().ToUpperInvariant();
            query = query.Where(x =>
                (x.UserName != null && x.UserName.ToUpper().Contains(userFilter)) ||
                x.Sid.ToUpper().Contains(userFilter) ||
                (x.UserPrincipalName != null && x.UserPrincipalName.ToUpper().Contains(userFilter)));
        }

        if (!string.IsNullOrWhiteSpace(artifactType))
        {
            var artifactTypeFilter = artifactType.Trim().ToUpperInvariant();
            query = query.Where(x => x.ArtifactType == artifactTypeFilter);
        }

        if (!string.IsNullOrWhiteSpace(profile))
        {
            var profileFilter = profile.Trim().ToUpperInvariant();
            query = query.Where(x =>
                x.ProfileName != null &&
                x.ProfileName.ToUpper().Contains(profileFilter));
        }

        var artifacts = await query
            .OrderBy(x => x.DeviceName)
            .ThenBy(x => x.UserName)
            .ThenBy(x => x.Path)
            .ToListAsync(cancellationToken);

        return Ok(artifacts.Select(x => new
        {
            deviceName = x.DeviceName,
            userName = x.UserName,
            sid = x.Sid,
            userPrincipalName = x.UserPrincipalName,
            profileName = x.ProfileName,
            artifactType = x.ArtifactType,
            path = x.Path,
            sizeBytes = x.SizeBytes,
            existsOnDisk = x.ExistsOnDisk,
            lastWriteUtc = x.LastWriteUtc,
            collectedUtc = x.CollectedUtc,
            scanStatus = x.Status,
            scanError = x.ErrorMessage
        }));
    }
}
