using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public sealed class InventoryQueryServiceTests
{
    [Fact]
    public async Task EmptyInventory_ReturnsEmptyListWithoutServerError()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var service = new InventoryQueryService(db);

        var devices = await service.GetLatestDevicesAsync(
            null, null, null, null, null, null, null, null, null, CancellationToken.None);

        Assert.Empty(devices);
    }

    [Fact]
    public async Task LatestOfflineSnapshot_PreservesLastInventoryAndLowersLicenseConfidence()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var successfulJob = new ScanJob { Status = JobStatus.Completed };
        var offlineJob = new ScanJob { Status = JobStatus.CompletedWithErrors };
        db.ScanJobs.AddRange(successfulJob, offlineJob);
        db.Devices.Add(new DeviceInventory
        {
            ScanJobId = successfulJob.Id,
            DeviceName = "PC-01",
            Ou = "OU=Old,DC=contoso,DC=local",
            Site = "ANKARA",
            CollectedUtc = DateTime.UtcNow.AddDays(-1),
            Status = DeviceScanStatus.Success,
            RawPayloadJson = "{\"schemaVersion\":\"1.2\"}",
            PstFiles =
            {
                new PstFileRecord
                {
                    Sid = "S-1-5-21-1-2-3-1001",
                    UserPrincipalName = "user@contoso.local",
                    ProfileName = "Outlook",
                    Path = @"C:\Users\user\mail.pst",
                    SizeBytes = 1024,
                    ExistsOnDisk = true
                }
            }
        });
        db.Devices.Add(new DeviceInventory
        {
            ScanJobId = offlineJob.Id,
            DeviceName = "pc-01",
            Ou = "OU=New,DC=contoso,DC=local",
            Site = "ISTANBUL",
            CollectedUtc = DateTime.UtcNow,
            Status = DeviceScanStatus.Offline,
            RawPayloadJson = "{}",
            ErrorMessage = "Offline"
        });
        await db.SaveChangesAsync();

        var service = new InventoryQueryService(db);
        var devices = await service.GetLatestDevicesAsync(
            null, null, null, null, null, null, null, null, null, CancellationToken.None);
        var recommendations = await service.GetLicenseRecommendationsAsync(CancellationToken.None);
        var movedScope = await service.GetLatestDevicesAsync(
            "OU=New", "ISTANBUL", null, null, null, null, "Offline", null, null, CancellationToken.None);
        var oldScope = await service.GetLatestDevicesAsync(
            "OU=Old", null, null, null, null, null, null, null, null, CancellationToken.None);

        var device = Assert.Single(devices);
        Assert.Equal(DeviceScanStatus.Offline, device.Status);
        Assert.Equal("OU=New,DC=contoso,DC=local", device.Ou);
        Assert.Equal("ISTANBUL", device.Site);
        Assert.Single(device.PstFiles);
        Assert.Single(movedScope);
        Assert.Empty(oldScope);
        var recommendation = Assert.Single(recommendations);
        Assert.Equal("user@contoso.local", recommendation.UserKey);
        Assert.Equal("Low", recommendation.Confidence);
    }
}
