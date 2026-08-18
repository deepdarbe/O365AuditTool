using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;

namespace O365AuditTool.Services;

public interface IScanJobCoordinator
{
    Task<Guid> EnqueueManualScanAsync(string requestedBy, string? ouFilter, string? siteFilter, CancellationToken cancellationToken);
}

public class ScanJobCoordinator(AuditDbContext dbContext) : IScanJobCoordinator
{
    public async Task<Guid> EnqueueManualScanAsync(string requestedBy, string? ouFilter, string? siteFilter, CancellationToken cancellationToken)
    {
        var normalizedOu = string.IsNullOrWhiteSpace(ouFilter) ? null : ouFilter.Trim();
        var normalizedSite = string.IsNullOrWhiteSpace(siteFilter) ? null : siteFilter.Trim();
        var activeJobs = await dbContext.ScanJobs
            .AsNoTracking()
            .Where(x => x.Status == JobStatus.Queued || x.Status == JobStatus.Running)
            .OrderByDescending(x => x.CreatedUtc)
            .Select(x => new { x.Id, x.OuFilter, x.SiteFilter })
            .ToListAsync(cancellationToken);
        var duplicate = activeJobs.FirstOrDefault(x =>
            string.Equals(x.OuFilter, normalizedOu, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.SiteFilter, normalizedSite, StringComparison.OrdinalIgnoreCase));
        if (duplicate is not null)
        {
            return duplicate.Id;
        }

        var job = new ScanJob
        {
            RequestedBy = requestedBy,
            OuFilter = normalizedOu,
            SiteFilter = normalizedSite,
            Status = JobStatus.Queued
        };

        dbContext.ScanJobs.Add(job);
        await dbContext.SaveChangesAsync(cancellationToken);
        return job.Id;
    }
}

public class ScanOrchestratorService(
    IServiceProvider serviceProvider,
    IOptions<CollectorOptions> options,
    ILogger<ScanOrchestratorService> logger) : BackgroundService
{
    private readonly CollectorOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var recoveryComplete = false;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!recoveryComplete)
                {
                    await RecoverInterruptedJobsAsync(stoppingToken);
                    recoveryComplete = true;
                }

                await TryScheduleDailyJobAsync(stoppingToken);

                var job = await TryClaimNextQueuedJobAsync(stoppingToken);
                if (job is not null)
                {
                    await RunClaimedJobSafelyAsync(job, stoppingToken);
                    continue;
                }

                await ProcessRetryQueueAsync(stoppingToken);
                await Task.Delay(PollingInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unhandled orchestration cycle failure; polling will continue");
                await DelayAfterFailureAsync(stoppingToken);
            }
        }
    }

    private TimeSpan PollingInterval =>
        TimeSpan.FromSeconds(Math.Max(1, _options.JobPollingSeconds));

    private int MaxDeviceParallelism =>
        Math.Max(1, _options.MaxDeviceParallelism);

    private async Task TryScheduleDailyJobAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.Now;
        var shouldRun = now.Hour > _options.DailyRunHour ||
                        (now.Hour == _options.DailyRunHour && now.Minute >= _options.DailyRunMinute);

        if (!shouldRun)
        {
            return;
        }

        using var scope = serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var startOfTodayUtc = now.Date.ToUniversalTime();
        var startOfTomorrowUtc = now.Date.AddDays(1).ToUniversalTime();
        var alreadyScheduled = await db.ScanJobs
            .AsNoTracking()
            .AnyAsync(
                x => x.RequestedBy == "scheduler" &&
                     x.CreatedUtc >= startOfTodayUtc &&
                     x.CreatedUtc < startOfTomorrowUtc,
                cancellationToken);

        if (alreadyScheduled)
        {
            return;
        }

        var job = BuildDailyScheduledJob(_options, DateTime.UtcNow);

        db.ScanJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);
        if (job.Status == JobStatus.Failed)
        {
            logger.LogError("Daily scan job {JobId} failed closed because no explicit AD scope is configured", job.Id);
        }
        else
        {
            logger.LogInformation(
                "Scheduled daily scan job {JobId} for OU scope {OuFilter} and site scope {SiteFilter}",
                job.Id,
                job.OuFilter,
                job.SiteFilter);
        }
    }

    internal static ScanJob BuildDailyScheduledJob(CollectorOptions options, DateTime utcNow)
    {
        var ouFilter = string.IsNullOrWhiteSpace(options.DefaultOuFilter)
            ? null
            : options.DefaultOuFilter.Trim();
        var siteFilter = string.IsNullOrWhiteSpace(options.DefaultSiteFilter)
            ? null
            : options.DefaultSiteFilter.Trim();

        if (ouFilter is null && siteFilter is null)
        {
            return new ScanJob
            {
                RequestedBy = "scheduler",
                Status = JobStatus.Failed,
                CreatedUtc = utcNow,
                CompletedUtc = utcNow,
                Notes = "Scheduled scan was not queued because both Collector:DefaultOuFilter and Collector:DefaultSiteFilter are empty. Configure an explicit AD scope."
            };
        }

        return new ScanJob
        {
            RequestedBy = "scheduler",
            OuFilter = ouFilter,
            SiteFilter = siteFilter,
            Status = JobStatus.Queued,
            CreatedUtc = utcNow
        };
    }

    private async Task<ScanJob?> TryClaimNextQueuedJobAsync(CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var candidate = await db.ScanJobs
            .AsNoTracking()
            .Where(x => x.Status == JobStatus.Queued)
            .OrderBy(x => x.CreatedUtc)
            .FirstOrDefaultAsync(cancellationToken);

        if (candidate is null)
        {
            return null;
        }

        var claimedUtc = DateTime.UtcNow;
        var claimed = await db.ScanJobs
            .Where(x => x.Id == candidate.Id && x.Status == JobStatus.Queued)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, JobStatus.Running)
                    .SetProperty(x => x.StartedUtc, claimedUtc)
                    .SetProperty(x => x.CompletedUtc, (DateTime?)null),
                cancellationToken);

        if (claimed == 0)
        {
            return null;
        }

        candidate.Status = JobStatus.Running;
        candidate.StartedUtc = claimedUtc;
        candidate.CompletedUtc = null;
        logger.LogInformation("Claimed queued scan job {JobId}", candidate.Id);
        return candidate;
    }

    private async Task RunClaimedJobSafelyAsync(ScanJob job, CancellationToken cancellationToken)
    {
        try
        {
            await RunJobAsync(job.Id, job.OuFilter, job.SiteFilter, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Scan job {JobId} failed", job.Id);
            await MarkJobFailedAsync(job.Id, ex, cancellationToken);
        }
    }

    private async Task RunJobAsync(Guid jobId, string? ouFilter, string? siteFilter, CancellationToken cancellationToken)
    {
        IReadOnlyList<DeviceTarget> targets;
        using (var scope = serviceProvider.CreateScope())
        {
            var targetProvider = scope.ServiceProvider.GetRequiredService<IDeviceTargetProvider>();
            targets = await targetProvider.GetTargetsAsync(ouFilter, siteFilter, cancellationToken);
        }

        if (targets.Count == 0)
        {
            throw new InvalidOperationException(
                "No target devices were discovered. Verify AD connectivity, OU filters, and fallback targets.");
        }

        var errorCount = 0;
        using var persistenceGate = new SemaphoreSlim(1, 1);

        await Parallel.ForEachAsync(
            targets,
            new ParallelOptions
            {
                CancellationToken = cancellationToken,
                MaxDegreeOfParallelism = MaxDeviceParallelism
            },
            async (target, deviceCancellationToken) =>
            {
                using var deviceScope = serviceProvider.CreateScope();
                var runner = deviceScope.ServiceProvider.GetRequiredService<IRemoteCollectorRunner>();
                var ingestor = deviceScope.ServiceProvider.GetRequiredService<IInventoryIngestionService>();
                var deviceDb = deviceScope.ServiceProvider.GetRequiredService<AuditDbContext>();

                try
                {
                    var result = await runner.RunAsync(target.Name, deviceCancellationToken);
                    await persistenceGate.WaitAsync(deviceCancellationToken);
                    try
                    {
                        if (result.Success && result.Payload is not null)
                        {
                            await ingestor.SavePayloadAsync(jobId, target, result.Payload, deviceCancellationToken);
                            if (result.Payload.Errors.Count > 0)
                            {
                                Interlocked.Increment(ref errorCount);
                            }
                        }
                        else
                        {
                            Interlocked.Increment(ref errorCount);
                            var item = await ingestor.SaveFailureAsync(
                                jobId,
                                target,
                                result.ErrorMessage ?? "Unknown error",
                                GetFailureStatus(result),
                                deviceCancellationToken);

                            if (item.Status == DeviceScanStatus.Offline)
                            {
                                await EnqueueRetryAsync(deviceDb, target, jobId, 1, deviceCancellationToken);
                            }
                        }
                    }
                    finally
                    {
                        persistenceGate.Release();
                    }
                }
                catch (OperationCanceledException) when (deviceCancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref errorCount);
                    logger.LogError(
                        ex,
                        "Unexpected scan failure for {Device} in job {JobId}",
                        target.Name,
                        jobId);

                    await PersistUnexpectedDeviceFailureAsync(
                        jobId,
                        target,
                        ex,
                        persistenceGate,
                        deviceCancellationToken);
                }
            });

        using var completionScope = serviceProvider.CreateScope();
        var db = completionScope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var job = await db.ScanJobs.SingleAsync(x => x.Id == jobId, cancellationToken);
        job.CompletedUtc = DateTime.UtcNow;
        job.Status = errorCount == 0 ? JobStatus.Completed : JobStatus.CompletedWithErrors;
        job.Notes = $"Targets={targets.Count}; Errors={errorCount}";
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task ProcessRetryQueueAsync(CancellationToken cancellationToken)
    {
        List<long> dueItemIds;
        using (var discoveryScope = serviceProvider.CreateScope())
        {
            var discoveryDb = discoveryScope.ServiceProvider.GetRequiredService<AuditDbContext>();
            dueItemIds = await discoveryDb.RetryQueue
                .AsNoTracking()
                .Where(x => x.NextAttemptUtc <= DateTime.UtcNow)
                .OrderBy(x => x.NextAttemptUtc)
                .Select(x => x.Id)
                .Take(20)
                .ToListAsync(cancellationToken);
        }

        using var persistenceGate = new SemaphoreSlim(1, 1);
        await Parallel.ForEachAsync(
            dueItemIds,
            new ParallelOptions
            {
                CancellationToken = cancellationToken,
                MaxDegreeOfParallelism = MaxDeviceParallelism
            },
            async (retryId, deviceCancellationToken) =>
            {
                try
                {
                    using var scope = serviceProvider.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
                    var runner = scope.ServiceProvider.GetRequiredService<IRemoteCollectorRunner>();
                    var ingestor = scope.ServiceProvider.GetRequiredService<IInventoryIngestionService>();
                    var retry = await db.RetryQueue
                        .SingleOrDefaultAsync(
                            x => x.Id == retryId && x.NextAttemptUtc <= DateTime.UtcNow,
                            deviceCancellationToken);

                    if (retry is null)
                    {
                        return;
                    }

                    var target = new DeviceTarget(retry.DeviceName, retry.Ou, retry.Site);
                    var result = await runner.RunAsync(retry.DeviceName, deviceCancellationToken);
                    await persistenceGate.WaitAsync(deviceCancellationToken);
                    try
                    {
                        if (result.Success && result.Payload is not null)
                        {
                            await ingestor.SavePayloadAsync(retry.ScanJobId, target, result.Payload, deviceCancellationToken);
                            db.RetryQueue.Remove(retry);
                        }
                        else
                        {
                            var failureStatus = GetFailureStatus(result);
                            await ingestor.SaveFailureAsync(
                                retry.ScanJobId,
                                target,
                                result.ErrorMessage ?? "Unknown retry error",
                                failureStatus,
                                deviceCancellationToken);

                            if (failureStatus != DeviceScanStatus.Offline)
                            {
                                logger.LogWarning(
                                    "Retry stopped for {Device} after non-offline failure {FailureStatus}",
                                    retry.DeviceName,
                                    failureStatus);
                                db.RetryQueue.Remove(retry);
                                await db.SaveChangesAsync(deviceCancellationToken);
                                await RefreshJobSummaryAfterRetryAsync(db, retry.ScanJobId, deviceCancellationToken);
                                return;
                            }

                            var maxAttempts = _options.RetryMinutes.Length;
                            retry.Attempt++;
                            if (retry.Attempt > maxAttempts)
                            {
                                logger.LogWarning("Retry attempts exhausted for {Device}", retry.DeviceName);
                                db.RetryQueue.Remove(retry);
                            }
                            else
                            {
                                var delay = _options.RetryMinutes[
                                    Math.Min(retry.Attempt - 1, _options.RetryMinutes.Length - 1)];
                                retry.NextAttemptUtc = DateTime.UtcNow.AddMinutes(delay);
                            }
                        }

                        await db.SaveChangesAsync(deviceCancellationToken);
                        await RefreshJobSummaryAfterRetryAsync(db, retry.ScanJobId, deviceCancellationToken);
                    }
                    finally
                    {
                        persistenceGate.Release();
                    }
                }
                catch (OperationCanceledException) when (deviceCancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Retry queue item {RetryId} failed; it remains queued", retryId);
                }
            });
    }

    private static async Task RefreshJobSummaryAfterRetryAsync(
        AuditDbContext db,
        Guid jobId,
        CancellationToken cancellationToken)
    {
        var statuses = await db.Devices
            .AsNoTracking()
            .Where(x => x.ScanJobId == jobId)
            .Select(x => x.Status)
            .ToListAsync(cancellationToken);
        var job = await db.ScanJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null)
        {
            return;
        }

        var errorCount = statuses.Count(status => status != DeviceScanStatus.Success);
        job.Status = errorCount == 0 ? JobStatus.Completed : JobStatus.CompletedWithErrors;
        job.CompletedUtc = DateTime.UtcNow;
        job.Notes = $"Targets={statuses.Count}; Errors={errorCount}; RetrySummaryUpdated=true";
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task RecoverInterruptedJobsAsync(CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var interruptedJobIds = await db.ScanJobs
            .AsNoTracking()
            .Where(x => x.Status == JobStatus.Running)
            .Select(x => x.Id)
            .ToListAsync(cancellationToken);

        if (interruptedJobIds.Count == 0)
        {
            return;
        }

        await db.Devices
            .Where(x => interruptedJobIds.Contains(x.ScanJobId))
            .ExecuteDeleteAsync(cancellationToken);
        await db.RetryQueue
            .Where(x => interruptedJobIds.Contains(x.ScanJobId))
            .ExecuteDeleteAsync(cancellationToken);
        await db.ScanJobs
            .Where(x => interruptedJobIds.Contains(x.Id))
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, JobStatus.Queued)
                    .SetProperty(x => x.StartedUtc, (DateTime?)null)
                    .SetProperty(x => x.CompletedUtc, (DateTime?)null)
                    .SetProperty(x => x.Notes, "Recovered after service restart."),
                cancellationToken);

        logger.LogWarning("Recovered {JobCount} interrupted scan job(s)", interruptedJobIds.Count);
    }

    private async Task MarkJobFailedAsync(Guid jobId, Exception exception, CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var message = $"Job failed: {exception.Message}";
        if (message.Length > 1024)
        {
            message = message[..1024];
        }

        await db.ScanJobs
            .Where(x => x.Id == jobId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, JobStatus.Failed)
                    .SetProperty(x => x.CompletedUtc, DateTime.UtcNow)
                    .SetProperty(x => x.Notes, message),
                cancellationToken);
    }

    private async Task EnqueueRetryAsync(
        AuditDbContext db,
        DeviceTarget target,
        Guid jobId,
        int attempt,
        CancellationToken cancellationToken)
    {
        var minutes = _options.RetryMinutes.Length == 0 ? 30 : _options.RetryMinutes[0];
        db.RetryQueue.Add(new RetryQueueItem
        {
            DeviceName = target.Name,
            Ou = target.Ou,
            Site = target.Site,
            ScanJobId = jobId,
            Attempt = attempt,
            NextAttemptUtc = DateTime.UtcNow.AddMinutes(minutes)
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task PersistUnexpectedDeviceFailureAsync(
        Guid jobId,
        DeviceTarget target,
        Exception exception,
        SemaphoreSlim persistenceGate,
        CancellationToken cancellationToken)
    {
        var message = $"Unexpected collector failure: {exception.Message}";
        if (message.Length > 4096)
        {
            message = message[..4096];
        }

        try
        {
            await persistenceGate.WaitAsync(cancellationToken);
            try
            {
                using var failureScope = serviceProvider.CreateScope();
                var failureIngestor = failureScope.ServiceProvider.GetRequiredService<IInventoryIngestionService>();
                await failureIngestor.SaveFailureAsync(
                    jobId,
                    target,
                    message,
                    DeviceScanStatus.Error,
                    cancellationToken);
            }
            finally
            {
                persistenceGate.Release();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception persistenceException)
        {
            logger.LogCritical(
                persistenceException,
                "Failed to persist unexpected scan failure for {Device} in job {JobId}",
                target.Name,
                jobId);
        }
    }

    internal static DeviceScanStatus GetFailureStatus(CollectResult result) =>
        result.IsTimedOut
            ? DeviceScanStatus.Timeout
            : result.IsOffline
                ? DeviceScanStatus.Offline
                : DeviceScanStatus.Error;

    private async Task DelayAfterFailureAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(PollingInterval, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal service shutdown.
        }
    }
}
