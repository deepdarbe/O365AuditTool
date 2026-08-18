using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;

namespace O365AuditTool.Services;

public sealed class RetentionOptions
{
    public int InventoryDays { get; set; } = 180;
    public int CopyJobDays { get; set; } = 365;
    public int InitialDelayMinutes { get; set; } = 5;
}

public sealed class DataRetentionService(
    IServiceProvider serviceProvider,
    IOptions<RetentionOptions> options,
    ILogger<DataRetentionService> logger) : BackgroundService
{
    private readonly RetentionOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(
            TimeSpan.FromMinutes(Math.Max(1, _options.InitialDelayMinutes)),
            stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PruneAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Inventory retention cleanup failed; the next daily run will retry");
            }

            await Task.Delay(TimeSpan.FromDays(1), stoppingToken);
        }
    }

    internal async Task PruneAsync(CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var inventoryCutoff = DateTime.UtcNow.AddDays(-Math.Max(30, _options.InventoryDays));
        var copyCutoff = DateTime.UtcNow.AddDays(-Math.Max(30, _options.CopyJobDays));

        var deletedScans = await db.ScanJobs
            .Where(x => x.CreatedUtc < inventoryCutoff &&
                        x.Status != JobStatus.Queued &&
                        x.Status != JobStatus.Running)
            .ExecuteDeleteAsync(cancellationToken);
        var deletedCopyJobs = await db.ArtifactCopyJobs
            .Where(x => x.CreatedUtc < copyCutoff &&
                        x.Status != CopyJobStatus.Planned &&
                        x.Status != CopyJobStatus.Queued &&
                        x.Status != CopyJobStatus.Running)
            .ExecuteDeleteAsync(cancellationToken);

        logger.LogInformation(
            "Retention cleanup removed {ScanJobs} scan job(s) and {CopyJobs} copy job(s)",
            deletedScans,
            deletedCopyJobs);
    }
}
