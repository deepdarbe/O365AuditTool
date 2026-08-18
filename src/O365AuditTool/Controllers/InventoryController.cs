using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using O365AuditTool.Models;
using O365AuditTool.Services;
using System.Text.Json;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/inventory")]
[Authorize(Policy = "AuditReader")]
public class InventoryController(IInventoryQueryService queryService) : ControllerBase
{
    [HttpGet("devices")]
    public async Task<IActionResult> GetDevices(
        [FromQuery] string? ou,
        [FromQuery] string? site,
        [FromQuery] string? device,
        [FromQuery] string? user,
        [FromQuery] string? diskType,
        [FromQuery] string? officeVersion,
        [FromQuery] string? status,
        [FromQuery] long? pstMinBytes,
        [FromQuery] long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var devices = await queryService.GetLatestDevicesAsync(ou, site, device, user, diskType, officeVersion, status, pstMinBytes, pstMaxBytes, cancellationToken);
        return Ok(devices.Select(d => new
        {
            d.Id,
            d.DeviceName,
            d.SerialNumber,
            d.Os,
            d.LastLoggedOnUser,
            d.CurrentLoggedOnUser,
            d.Ou,
            d.Site,
            d.CollectedUtc,
            d.Status,
            d.ErrorMessage,
            ipAddresses = ParseIpAddresses(d.IpAddressesJson),
            pstTotalBytes = d.PstFiles.Sum(x => x.SizeBytes),
            disks = d.Disks.Select(x => new { x.Model, x.InterfaceType, x.BusType, x.MediaType, x.SizeBytes }),
            volumes = d.Volumes.Select(x => new { x.Name, x.TotalBytes, x.FreeBytes, x.FileSystem }),
            officeProducts = d.OfficeProducts.Select(x => new { x.Name, x.Version, x.InstallType, x.Architecture, x.UpdateChannel, x.ProductIds, x.UpdatesEnabled }),
            officeProcesses = d.OfficeProcesses.Select(x => new { x.ProcessName, x.IsRunning, x.Pid, x.StartTimeUtc, x.Owner, x.SessionId }),
            profiles = d.Profiles.Select(x => new { x.Sid, x.ProfileName, x.ProfilePath, x.UserName, x.Loaded, x.IsDefault }),
            mailAccounts = d.MailAccounts.Select(x => new { x.Sid, x.ProfileName, x.AccountType, x.Address, x.IsActive }),
            pstFiles = d.PstFiles.Select(x => new { x.Sid, x.UserPrincipalName, x.ProfileName, x.Path, x.SizeBytes, x.ExistsOnDisk, x.LastWriteUtc }),
            legacyFiles = d.LegacyFiles.Select(x => new { x.Sid, x.UserName, x.UserPrincipalName, x.ProfileName, x.ArtifactType, x.Path, x.SizeBytes, x.ExistsOnDisk, x.LastWriteUtc })
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
            confidence = x.Confidence,
            assessmentType = x.AssessmentType,
            requiresTenantValidation = x.RequiresTenantValidation,
            caveat = x.Caveat
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
        var snapshots = await queryService.GetLatestDevicesAsync(
            null, null, device, null, null, null, null, null, null, cancellationToken);
        var query = snapshots.SelectMany(snapshot => snapshot.LegacyFiles.Select(legacyFile => new
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
        }));

        if (!string.IsNullOrWhiteSpace(user))
        {
            var userFilter = user.Trim().ToUpperInvariant();
            query = query.Where(x =>
                (x.UserName?.Contains(userFilter, StringComparison.OrdinalIgnoreCase) ?? false) ||
                x.Sid.Contains(userFilter, StringComparison.OrdinalIgnoreCase) ||
                (x.UserPrincipalName?.Contains(userFilter, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        if (!string.IsNullOrWhiteSpace(artifactType))
        {
            var artifactTypeFilter = artifactType.Trim().ToUpperInvariant();
            query = query.Where(x => string.Equals(x.ArtifactType, artifactTypeFilter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(profile))
        {
            var profileFilter = profile.Trim().ToUpperInvariant();
            query = query.Where(x =>
                x.ProfileName?.Contains(profileFilter, StringComparison.OrdinalIgnoreCase) ?? false);
        }

        var artifacts = query
            .OrderBy(x => x.DeviceName)
            .ThenBy(x => x.UserName)
            .ThenBy(x => x.Path)
            .ToList();

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

    private static string[] ParseIpAddresses(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(value) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
