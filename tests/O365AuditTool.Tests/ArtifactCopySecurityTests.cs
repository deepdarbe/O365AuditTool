using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class ArtifactCopySecurityTests
{
    [Fact]
    public void CopyOptions_DefaultToSha256VerificationAndDisabledUncSources()
    {
        var options = new CopyOptions();

        Assert.True(options.VerifySha256);
        Assert.Empty(options.AllowedSourceUncRoots);
    }

    [Fact]
    public async Task ExistingDestination_WithSameLengthAndDifferentContent_IsNotAccepted()
    {
        var directory = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(directory, "source.pst");
        var destinationPath = Path.Combine(directory, "destination.pst");
        await File.WriteAllTextAsync(sourcePath, "AAAA");
        await File.WriteAllTextAsync(destinationPath, "BBBB");

        try
        {
            await using var source = ArtifactCopyService.OpenSourceExclusive(sourcePath);
            var result = await ArtifactCopyService.VerifyExistingDestinationAsync(
                source,
                sourcePath,
                source.Length,
                File.GetLastWriteTimeUtc(sourcePath),
                destinationPath,
                CancellationToken.None);

            Assert.False(result.IsSame);
            Assert.NotNull(result.Sha256);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void OpenSourceExclusive_FailsWithOutlookOrVssGuidanceWhenFileIsInUse()
    {
        var directory = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(directory, "active.pst");
        File.WriteAllText(sourcePath, "mail-data");

        try
        {
            using var activeWriter = new FileStream(
                sourcePath,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.ReadWrite);

            var exception = Assert.Throws<IOException>(() =>
                ArtifactCopyService.OpenSourceExclusive(sourcePath));

            Assert.Contains("Close Outlook", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("VSS", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task CreatePlan_RejectsEmptyPlan()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;
        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var service = new ArtifactCopyPlanService(
            db,
            Options.Create(new CopyOptions { DefaultTargetRoot = @"C:\MigrationRoot" }));

        var exception = await Assert.ThrowsAsync<ArtifactCopyValidationException>(() =>
            service.CreatePlanAsync(
                new CreateCopyPlanRequest(null, ["NO-SUCH-DEVICE"], null, ["PST"]),
                @"CONTOSO\planner",
                CancellationToken.None));

        Assert.Contains("no artifacts", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(db.ArtifactCopyJobs);
    }

    [Fact]
    public async Task CreatePlan_RejectsOversizedSourcePathInsteadOfTruncating()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;
        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();

        var scanJob = new ScanJob();
        scanJob.Devices.Add(new DeviceInventory
        {
            ScanJobId = scanJob.Id,
            DeviceName = "PC-001",
            CollectedUtc = DateTime.UtcNow,
            Status = DeviceScanStatus.Success,
            PstFiles =
            [
                new PstFileRecord
                {
                    Sid = "S-1-5-21-1",
                    Path = @"C:\" + new string('a', 1020) + ".pst",
                    SizeBytes = 4,
                    ExistsOnDisk = true
                }
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

        Assert.Contains("1024 character limit", exception.Message, StringComparison.Ordinal);
        Assert.Contains("not truncated", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueuePlan_ConcurrentRequestsHaveSingleWinnerAndDoNotRegressStatus()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"o365-copy-{Guid.NewGuid():N}.db");
        var targetRoot = CreateTemporaryDirectory();
        var connectionString = $"Data Source={databasePath};Default Timeout=30";
        var dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connectionString)
            .Options;
        var jobId = Guid.NewGuid();

        try
        {
            await using (var setupDb = new AuditDbContext(dbOptions))
            {
                await setupDb.Database.EnsureCreatedAsync();
                setupDb.ArtifactCopyJobs.Add(new ArtifactCopyJob
                {
                    Id = jobId,
                    TargetRoot = targetRoot,
                    Status = CopyJobStatus.Planned,
                    Items =
                    [
                        new ArtifactCopyItem
                        {
                            DeviceName = "PC-001",
                            UserKey = "user@example.com",
                            ProfileName = "Outlook",
                            ArtifactType = "PST",
                            SourcePath = @"C:\Users\User\mail.pst",
                            SourceSizeBytes = 4,
                            DestinationPath = Path.Combine(targetRoot, "user", "PC-001", "mail.pst"),
                            Status = CopyItemStatus.Planned
                        }
                    ]
                });
                await setupDb.SaveChangesAsync();
            }

            var copyOptions = Options.Create(new CopyOptions
            {
                Enabled = true,
                AllowedTargetRoots = [targetRoot]
            });
            await using var firstDb = new AuditDbContext(dbOptions);
            await using var secondDb = new AuditDbContext(dbOptions);
            var firstService = new ArtifactCopyPlanService(firstDb, copyOptions);
            var secondService = new ArtifactCopyPlanService(secondDb, copyOptions);

            var outcomes = await Task.WhenAll(
                TryQueueAsync(firstService, jobId),
                TryQueueAsync(secondService, jobId));

            Assert.Single(outcomes, x => x == "queued");
            Assert.Single(outcomes, x => x == "conflict");

            await using var verificationDb = new AuditDbContext(dbOptions);
            var storedJob = await verificationDb.ArtifactCopyJobs
                .Include(x => x.Items)
                .SingleAsync(x => x.Id == jobId);
            Assert.Equal(CopyJobStatus.Queued, storedJob.Status);
            Assert.All(storedJob.Items, x => Assert.Equal(CopyItemStatus.Queued, x.Status));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }

            Directory.Delete(targetRoot, recursive: true);
        }
    }

    private static async Task<string> TryQueueAsync(
        ArtifactCopyPlanService service,
        Guid jobId)
    {
        try
        {
            await service.QueuePlanAsync(jobId, "CONTOSO\\admin", CancellationToken.None);
            return "queued";
        }
        catch (ArtifactCopyConflictException)
        {
            return "conflict";
        }
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"o365-copy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
