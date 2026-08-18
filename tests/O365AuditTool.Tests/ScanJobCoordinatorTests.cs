using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class ScanJobCoordinatorTests
{
    [Fact]
    public async Task EnqueueManualScan_PersistsDurableQueuedJob()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var coordinator = new ScanJobCoordinator(db);

        var jobId = await coordinator.EnqueueManualScanAsync(
            "DOMAIN\\operator",
            "OU=Workstations",
            "IST-SITE",
            CancellationToken.None);

        var job = await db.ScanJobs.AsNoTracking().SingleAsync(x => x.Id == jobId);
        Assert.Equal(JobStatus.Queued, job.Status);
        Assert.Equal("DOMAIN\\operator", job.RequestedBy);
        Assert.Equal("OU=Workstations", job.OuFilter);
        Assert.Equal("IST-SITE", job.SiteFilter);
    }

    [Fact]
    public async Task EnqueueManualScan_ReusesActiveJobForSameScope()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new AuditDbContext(options);
        await db.Database.EnsureCreatedAsync();
        var coordinator = new ScanJobCoordinator(db);

        var firstId = await coordinator.EnqueueManualScanAsync(
            "DOMAIN\\operator1",
            "OU=Workstations,DC=example,DC=local",
            "IST-SITE",
            CancellationToken.None);
        var secondId = await coordinator.EnqueueManualScanAsync(
            "DOMAIN\\operator2",
            "  ou=workstations,dc=example,dc=local  ",
            "ist-site",
            CancellationToken.None);

        Assert.Equal(firstId, secondId);
        Assert.Equal(1, await db.ScanJobs.CountAsync());
    }
}
