using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class DataRetentionServiceTests
{
    [Fact]
    public async Task PruneAsync_RemovesOnlyExpiredTerminalJobs()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddDbContext<AuditDbContext>(options => options.UseSqlite(connection));
        await using var provider = services.BuildServiceProvider();

        Guid expiredScanId;
        Guid runningScanId;
        Guid expiredCopyId;
        Guid plannedCopyId;
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            await db.Database.EnsureCreatedAsync();
            var expiredScan = new ScanJob { CreatedUtc = DateTime.UtcNow.AddDays(-40), Status = JobStatus.Completed };
            var runningScan = new ScanJob { CreatedUtc = DateTime.UtcNow.AddDays(-40), Status = JobStatus.Running };
            var expiredCopy = new ArtifactCopyJob
            {
                CreatedUtc = DateTime.UtcNow.AddDays(-40),
                Status = CopyJobStatus.Completed,
                TargetRoot = @"C:\Migration"
            };
            var plannedCopy = new ArtifactCopyJob
            {
                CreatedUtc = DateTime.UtcNow.AddDays(-40),
                Status = CopyJobStatus.Planned,
                TargetRoot = @"C:\Migration"
            };
            db.AddRange(expiredScan, runningScan, expiredCopy, plannedCopy);
            await db.SaveChangesAsync();
            expiredScanId = expiredScan.Id;
            runningScanId = runningScan.Id;
            expiredCopyId = expiredCopy.Id;
            plannedCopyId = plannedCopy.Id;
        }

        var service = new DataRetentionService(
            provider,
            Options.Create(new RetentionOptions { InventoryDays = 30, CopyJobDays = 30 }),
            NullLogger<DataRetentionService>.Instance);
        await service.PruneAsync(CancellationToken.None);

        await using var verificationScope = provider.CreateAsyncScope();
        var verificationDb = verificationScope.ServiceProvider.GetRequiredService<AuditDbContext>();
        Assert.False(await verificationDb.ScanJobs.AnyAsync(x => x.Id == expiredScanId));
        Assert.True(await verificationDb.ScanJobs.AnyAsync(x => x.Id == runningScanId));
        Assert.False(await verificationDb.ArtifactCopyJobs.AnyAsync(x => x.Id == expiredCopyId));
        Assert.True(await verificationDb.ArtifactCopyJobs.AnyAsync(x => x.Id == plannedCopyId));
    }
}
