using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class ArtifactCopyPlanServiceTests
{
    [Fact]
    public async Task CreatePlan_RejectsSamePhysicalArtifactWithDifferentOwners()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;
        await using var db = new AuditDbContext(dbOptions);
        await db.Database.EnsureCreatedAsync();

        var scanJob = new ScanJob();
        scanJob.Devices.Add(new DeviceInventory
        {
            ScanJobId = scanJob.Id,
            DeviceName = "PC-01",
            CollectedUtc = DateTime.UtcNow,
            Status = DeviceScanStatus.Success,
            RawPayloadJson = "{}",
            PstFiles =
            [
                new PstFileRecord { Sid = "SID-A", UserPrincipalName = "a@example.com", ProfileName = "A", Path = @"C:\Shared\mail.pst", SizeBytes = 10, ExistsOnDisk = true },
                new PstFileRecord { Sid = "SID-B", UserPrincipalName = "b@example.com", ProfileName = "B", Path = @"C:\Shared\mail.pst", SizeBytes = 10, ExistsOnDisk = true }
            ]
        });
        db.ScanJobs.Add(scanJob);
        await db.SaveChangesAsync();

        var service = new ArtifactCopyPlanService(
            db,
            Options.Create(new CopyOptions { DefaultTargetRoot = @"C:\MigrationRoot" }));

        var exception = await Assert.ThrowsAsync<ArtifactCopyValidationException>(() =>
            service.CreatePlanAsync(
                new CreateCopyPlanRequest(null, null, null, ["PST"]),
                @"CONTOSO\planner",
                CancellationToken.None));

        Assert.Contains("ownership is ambiguous", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreatePlan_UsesLatestUsableSnapshotAndBuildsAccountDeviceProfileHierarchy()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(dbOptions);
        await db.Database.EnsureCreatedAsync();

        var job = new ScanJob();
        var device = new DeviceInventory
        {
            ScanJobId = job.Id,
            DeviceName = "PC-FIN-01",
            CollectedUtc = DateTime.UtcNow,
            Status = DeviceScanStatus.Error,
            RawPayloadJson = """{"schemaVersion":"1.1","errors":["one inaccessible profile"]}""",
            MailAccounts =
            [
                new MailAccount
                {
                    Sid = "S-1-5-21-100",
                    ProfileName = "Outlook",
                    Address = "ada@example.com",
                    AccountType = "Exchange"
                },
                new MailAccount
                {
                    Sid = "S-1-5-21-100",
                    ProfileName = "Archive",
                    Address = "archive@example.com",
                    AccountType = "IMAP"
                }
            ],
            PstFiles =
            [
                new PstFileRecord
                {
                    Sid = "S-1-5-21-100",
                    UserPrincipalName = null,
                    ProfileName = "Outlook",
                    Path = @"C:\Users\Ada\Documents\Outlook Files\archive.pst",
                    SizeBytes = 1024,
                    ExistsOnDisk = true,
                    LastWriteUtc = DateTime.UtcNow.AddMinutes(-5)
                }
            ],
            LegacyFiles =
            [
                new LegacyMailFileRecord
                {
                    Sid = "S-1-5-21-100",
                    UserName = @"CONTOSO\ada",
                    UserPrincipalName = "ada@example.com",
                    ProfileName = "Outlook",
                    ArtifactType = "NK2",
                    Path = @"C:\Users\Ada\AppData\Roaming\Microsoft\Outlook\Outlook.nk2",
                    SizeBytes = 256,
                    ExistsOnDisk = true,
                    LastWriteUtc = DateTime.UtcNow.AddMinutes(-5)
                }
            ]
        };

        job.Devices.Add(device);
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();

        var service = new ArtifactCopyPlanService(
            db,
            Options.Create(new CopyOptions { DefaultTargetRoot = @"C:\MigrationRoot" }));

        var plan = await service.CreatePlanAsync(
            new CreateCopyPlanRequest(null, ["PC-FIN-01"], ["ada@example.com"], ["PST", "NK2"]),
            @"CONTOSO\planner",
            CancellationToken.None);

        Assert.Equal(CopyJobStatus.Planned, plan.Status);
        Assert.Equal(2, plan.Items.Count);
        Assert.All(plan.Items, item =>
        {
            Assert.Equal("ada@example.com", item.UserKey);
            Assert.Equal("PC-FIN-01", item.DeviceName);
            Assert.Equal("Outlook", item.ProfileName);
            Assert.StartsWith(
                @"C:\MigrationRoot\ada@example.com\PC-FIN-01\Outlook\",
                item.DestinationPath,
                StringComparison.OrdinalIgnoreCase);
        });
        Assert.Contains(plan.Items, x => x.ArtifactType == "PST");
        Assert.Contains(plan.Items, x => x.ArtifactType == "NK2");
    }
}
