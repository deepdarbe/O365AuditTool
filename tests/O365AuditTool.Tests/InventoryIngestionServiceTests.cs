using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class InventoryIngestionServiceTests
{
    [Fact]
    public async Task SavePayload_NormalizesAndDeduplicatesLegacyFiles()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();

        var job = new ScanJob();
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();

        var payload = new CollectorPayload
        {
            Device = new CollectorDevice
            {
                Hostname = "PC01",
                CurrentLoggedOnUser = @"CONTOSO\ada"
            },
            LegacyFiles =
            [
                Legacy("S-1-5-21-1", @"C:\Users\Ada\AppData\Roaming\Microsoft\Outlook\Ada.nk2", "nk2"),
                Legacy("S-1-5-21-1", @"c:\users\ada\appdata\roaming\microsoft\outlook\ada.nk2", "NK2"),
                Legacy("S-1-5-21-1", @"C:\Users\Ada\file.tmp", "TMP"),
                Legacy("S-1-5-21-1", " ", "N2K")
            ]
        };

        var service = new InventoryIngestionService(db);
        await service.SavePayloadAsync(job.Id, new DeviceTarget("PC01"), payload, CancellationToken.None);

        var stored = await db.LegacyFiles.AsNoTracking().SingleAsync();
        Assert.Equal("NK2", stored.ArtifactType);
        Assert.Equal(@"C:\Users\Ada\AppData\Roaming\Microsoft\Outlook\Ada.nk2", stored.Path);
    }

    [Fact]
    public async Task SavePayload_PersistsProfilePstAndOfficeProcessMetadata()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();

        var job = new ScanJob();
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();

        var payload = new CollectorPayload
        {
            Device = new CollectorDevice
            {
                Hostname = "PC01",
                CurrentLoggedOnUser = @"CONTOSO\ada"
            },
            Profiles =
            [
                new CollectorProfile
                {
                    Sid = "S-1-12-1-1-2-3-4",
                    ProfileName = "M365",
                    ProfilePath = @"C:\Users\Ada",
                    UserName = @"AzureAD\ada",
                    Loaded = true
                }
            ],
            PstFiles =
            [
                new CollectorPstFile
                {
                    Sid = "S-1-12-1-1-2-3-4",
                    ProfileName = "M365",
                    Path = @"C:\Users\Ada\mail.pst"
                }
            ],
            Office = new CollectorOffice
            {
                InstalledProducts =
                [
                    new CollectorOfficeProduct
                    {
                        Name = "Microsoft Office Click-to-Run",
                        Version = "16.0.19029.20136",
                        InstallType = "ClickToRun",
                        Architecture = "x64",
                        UpdateChannel = "Current",
                        ProductIds = "O365ProPlusRetail",
                        UpdatesEnabled = true
                    }
                ],
                RunningProcesses =
                [
                    new CollectorOfficeProcess
                    {
                        ProcessName = "OUTLOOK",
                        Pid = 42,
                        IsRunning = true,
                        Owner = @"AzureAD\ada",
                        SessionId = 3
                    }
                ]
            }
        };

        var service = new InventoryIngestionService(db);
        await service.SavePayloadAsync(job.Id, new DeviceTarget("PC01"), payload, CancellationToken.None);

        var profile = await db.Set<MailProfile>().AsNoTracking().SingleAsync();
        Assert.Equal(@"C:\Users\Ada", profile.ProfilePath);
        Assert.Equal(@"AzureAD\ada", profile.UserName);
        Assert.True(profile.Loaded);
        Assert.Equal("M365", (await db.PstFiles.AsNoTracking().SingleAsync()).ProfileName);
        var process = await db.Set<OfficeProcess>().AsNoTracking().SingleAsync();
        Assert.Equal(@"AzureAD\ada", process.Owner);
        Assert.Equal(3, process.SessionId);
        var product = await db.Set<OfficeProduct>().AsNoTracking().SingleAsync();
        Assert.Equal("x64", product.Architecture);
        Assert.Equal("Current", product.UpdateChannel);
        Assert.True(product.UpdatesEnabled);
        Assert.Equal(@"CONTOSO\ada", (await db.Devices.AsNoTracking().SingleAsync()).CurrentLoggedOnUser);
    }

    [Fact]
    public async Task SavePayload_WithCollectorErrors_DoesNotStoreSuccess()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();

        var job = new ScanJob();
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();

        var payload = new CollectorPayload
        {
            Device = new CollectorDevice { Hostname = "PC01" },
            Errors = ["outlook [S-1-5-21-1-2-3-1001] hive mount failed"]
        };

        var service = new InventoryIngestionService(db);
        var stored = await service.SavePayloadAsync(
            job.Id,
            new DeviceTarget("PC01"),
            payload,
            CancellationToken.None);

        Assert.Equal(DeviceScanStatus.Partial, stored.Status);
        Assert.Contains("hive mount", stored.ErrorMessage);
    }

    [Fact]
    public async Task SaveFailure_PersistsTimeoutWithoutMarkingDeviceOffline()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var job = new ScanJob();
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();

        var service = new InventoryIngestionService(db);
        var stored = await service.SaveFailureAsync(
            job.Id,
            new DeviceTarget("PC01"),
            "Collector timed out.",
            DeviceScanStatus.Timeout,
            CancellationToken.None);

        Assert.Equal(DeviceScanStatus.Timeout, stored.Status);
    }

    [Fact]
    public async Task RetryResult_ReplacesPreviousAttemptForSameJobAndDevice()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;
        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var job = new ScanJob();
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();
        var service = new InventoryIngestionService(db);

        await service.SaveFailureAsync(
            job.Id,
            new DeviceTarget("PC01"),
            "offline",
            DeviceScanStatus.Offline,
            CancellationToken.None);
        await service.SavePayloadAsync(
            job.Id,
            new DeviceTarget("pc01"),
            new CollectorPayload { Device = new CollectorDevice { Hostname = "PC01" } },
            CancellationToken.None);

        var stored = await db.Devices.AsNoTracking().Where(x => x.ScanJobId == job.Id).ToListAsync();
        Assert.Single(stored);
        Assert.Equal(DeviceScanStatus.Success, stored[0].Status);
    }

    private static CollectorLegacyFile Legacy(string sid, string path, string type) =>
        new()
        {
            Sid = sid,
            Path = path,
            ArtifactType = type,
            ExistsOnDisk = true,
            SizeBytes = 42
        };
}
