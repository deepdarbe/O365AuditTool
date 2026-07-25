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
            Device = new CollectorDevice { Hostname = "PC01" },
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
