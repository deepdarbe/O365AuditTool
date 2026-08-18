using System.Data;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;

[assembly: InternalsVisibleTo("O365AuditTool.Tests")]

namespace O365AuditTool.Services;

public interface IArtifactCopyPlanService
{
    Task<ArtifactCopyJob> CreatePlanAsync(
        CreateCopyPlanRequest request,
        string requestedBy,
        CancellationToken cancellationToken);

    Task<ArtifactCopyJob?> GetPlanAsync(Guid id, CancellationToken cancellationToken);

    Task<List<ArtifactCopyJob>> ListPlansAsync(int take, CancellationToken cancellationToken);

    Task<ArtifactCopyJob?> QueuePlanAsync(Guid id, string executedBy, CancellationToken cancellationToken);
}

public sealed class ArtifactCopyValidationException(string message) : Exception(message);

public sealed class ArtifactCopyDisabledException(string message) : Exception(message);

public sealed class ArtifactCopyConflictException(string message) : Exception(message);

public sealed class ArtifactCopyPlanService(
    AuditDbContext db,
    IOptions<CopyOptions> options) : IArtifactCopyPlanService
{
    private static readonly string[] DefaultArtifactTypes = ["PST", "NK2", "N2K"];
    private readonly CopyOptions _options = options.Value;

    public async Task<ArtifactCopyJob> CreatePlanAsync(
        CreateCopyPlanRequest request,
        string requestedBy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var targetRoot = string.IsNullOrWhiteSpace(request.TargetRoot)
            ? _options.DefaultTargetRoot
            : request.TargetRoot;
        var normalizedTargetRoot = RequireWithinLimit(
            ArtifactCopyPath.NormalizeRoot(targetRoot),
            1024,
            "Target root");
        var deviceFilter = BuildFilter(request.Devices);
        var userFilter = BuildFilter(request.Users);
        var artifactTypes = NormalizeArtifactTypes(request.ArtifactTypes);

        var latestUsableIds = await db.Devices
            .AsNoTracking()
            .Where(x =>
                x.Status == DeviceScanStatus.Success ||
                x.Status == DeviceScanStatus.Partial ||
                (x.Status == DeviceScanStatus.Error && x.RawPayloadJson != "{}"))
            .GroupBy(x => x.DeviceName.ToUpper())
            .Select(group => group
                .OrderByDescending(x => x.CollectedUtc)
                .ThenByDescending(x => x.Id)
                .Select(x => x.Id)
                .First())
            .ToListAsync(cancellationToken);

        var snapshots = await db.Devices
            .AsNoTracking()
            .AsSplitQuery()
            .Where(x => latestUsableIds.Contains(x.Id))
            .Include(x => x.PstFiles)
            .Include(x => x.LegacyFiles)
            .Include(x => x.MailAccounts)
            .Include(x => x.Profiles)
            .OrderBy(x => x.DeviceName)
            .ToListAsync(cancellationToken);

        var job = new ArtifactCopyJob
        {
            RequestedBy = Limit(requestedBy, 128, "unknown"),
            TargetRoot = normalizedTargetRoot,
            Status = CopyJobStatus.Planned
        };

        var sourceOwners = new Dictionary<string, (string UserKey, string ProfileName)>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var device in snapshots)
        {
            if (deviceFilter.Count > 0 && !deviceFilter.Contains(device.DeviceName))
            {
                continue;
            }

            if (artifactTypes.Contains("PST"))
            {
                foreach (var pst in device.PstFiles.Where(x => x.ExistsOnDisk && !string.IsNullOrWhiteSpace(x.Path)))
                {
                    var account = ResolvePstAccount(device, pst);
                    if (!MatchesUserFilter(userFilter, account.UserKey, pst.Sid, account.ProfileName))
                    {
                        continue;
                    }

                    AddItem(
                        job,
                        sourceOwners,
                        device.DeviceName,
                        account.UserKey,
                        account.ProfileName,
                        "PST",
                        pst.Path,
                        pst.SizeBytes,
                        pst.LastWriteUtc);
                }
            }

            foreach (var legacy in device.LegacyFiles.Where(x =>
                         x.ExistsOnDisk &&
                         !string.IsNullOrWhiteSpace(x.Path) &&
                         artifactTypes.Contains(x.ArtifactType)))
            {
                var userKey = FirstNonEmpty(
                    legacy.UserPrincipalName,
                    legacy.UserName,
                    ResolveAccountAddress(device, legacy.Sid, legacy.ProfileName),
                    $"SID:{legacy.Sid}");
                var profileName = FirstNonEmpty(
                    legacy.ProfileName,
                    ResolveProfileName(device, legacy.Sid),
                    "Default");

                if (!MatchesUserFilter(userFilter, userKey, legacy.Sid, profileName))
                {
                    continue;
                }

                AddItem(
                    job,
                    sourceOwners,
                    device.DeviceName,
                    userKey,
                    profileName,
                    legacy.ArtifactType.ToUpperInvariant(),
                    legacy.Path,
                    legacy.SizeBytes,
                    legacy.LastWriteUtc);
            }
        }

        if (job.Items.Count == 0)
        {
            throw new ArtifactCopyValidationException(
                "Copy plan contains no artifacts. Adjust the device, user, or artifact type filters.");
        }

        job.Notes = $"SnapshotItems={job.Items.Count}; ArtifactTypes={string.Join(',', artifactTypes.Order())}";
        db.ArtifactCopyJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);
        return job;
    }

    public Task<ArtifactCopyJob?> GetPlanAsync(Guid id, CancellationToken cancellationToken)
    {
        return db.ArtifactCopyJobs
            .AsNoTracking()
            .Include(x => x.Items)
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
    }

    public Task<List<ArtifactCopyJob>> ListPlansAsync(int take, CancellationToken cancellationToken)
    {
        var boundedTake = Math.Clamp(take, 1, 100);
        return db.ArtifactCopyJobs
            .AsNoTracking()
            .Include(x => x.Items)
            .OrderByDescending(x => x.CreatedUtc)
            .Take(boundedTake)
            .ToListAsync(cancellationToken);
    }

    public async Task<ArtifactCopyJob?> QueuePlanAsync(Guid id, string executedBy, CancellationToken cancellationToken)
    {
        var job = await db.ArtifactCopyJobs
            .AsNoTracking()
            .Include(x => x.Items)
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (job is null)
        {
            return null;
        }

        if (!_options.Enabled)
        {
            throw new ArtifactCopyDisabledException(
                "Artifact copy is disabled. Set Copy:Enabled=true after validating source and target permissions.");
        }

        if (job.Status != CopyJobStatus.Planned)
        {
            throw new ArtifactCopyConflictException(
                $"Only Planned jobs can be queued. Current status: {job.Status}.");
        }

        if (job.Items.Count == 0)
        {
            throw new ArtifactCopyValidationException("Empty copy plans cannot be queued.");
        }

        if (job.Items.Any(x => x.Status != CopyItemStatus.Planned))
        {
            throw new ArtifactCopyConflictException(
                "Only plans whose items are all Planned can be queued.");
        }

        if (!ArtifactCopyPath.TryValidateAllowedRoot(
                job.TargetRoot,
                _options.AllowedTargetRoots,
                out var normalizedTargetRoot,
                out var validationError))
        {
            throw new ArtifactCopyValidationException(validationError);
        }

        normalizedTargetRoot = RequireWithinLimit(normalizedTargetRoot, 1024, "Target root");
        var normalizedExecutedBy = RequireWithinLimit(executedBy, 128, "Executed by");
        var queuedUtc = DateTime.UtcNow;
        foreach (var item in job.Items)
        {
            ValidatePersistedItem(item);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken);
        var claimed = await db.ArtifactCopyJobs
            .Where(x => x.Id == id && x.Status == CopyJobStatus.Planned)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.TargetRoot, normalizedTargetRoot)
                    .SetProperty(x => x.Status, CopyJobStatus.Queued)
                    .SetProperty(x => x.ExecutedBy, normalizedExecutedBy)
                    .SetProperty(x => x.QueuedUtc, queuedUtc)
                    .SetProperty(x => x.StartedUtc, (DateTime?)null)
                    .SetProperty(x => x.CompletedUtc, (DateTime?)null),
                cancellationToken);
        if (claimed != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            throw new ArtifactCopyConflictException(
                "The copy plan was queued or changed by another request.");
        }

        var queuedItems = await db.ArtifactCopyItems
            .Where(x => x.ArtifactCopyJobId == id && x.Status == CopyItemStatus.Planned)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, CopyItemStatus.Queued)
                    .SetProperty(x => x.ErrorMessage, (string?)null),
                cancellationToken);
        if (queuedItems != job.Items.Count)
        {
            await transaction.RollbackAsync(cancellationToken);
            throw new ArtifactCopyConflictException(
                "One or more copy items changed while the plan was being queued.");
        }

        await transaction.CommitAsync(cancellationToken);
        return await GetPlanAsync(id, cancellationToken);
    }

    private static HashSet<string> BuildFilter(IEnumerable<string>? values)
    {
        return values?
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    private static HashSet<string> NormalizeArtifactTypes(IEnumerable<string>? requestedTypes)
    {
        var values = requestedTypes?
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim().ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        values = values is null or { Length: 0 } ? DefaultArtifactTypes : values;

        var unsupported = values
            .Except(DefaultArtifactTypes, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (unsupported.Length > 0)
        {
            throw new ArtifactCopyValidationException(
                $"Unsupported artifact type(s): {string.Join(", ", unsupported)}. Supported values: PST, NK2, N2K.");
        }

        return values.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static bool MatchesUserFilter(
        HashSet<string> userFilter,
        string userKey,
        string sid,
        string? profileName)
    {
        return userFilter.Count == 0 ||
               userFilter.Contains(userKey) ||
               userFilter.Contains(sid) ||
               (!string.IsNullOrWhiteSpace(profileName) && userFilter.Contains(profileName));
    }

    private static (string UserKey, string ProfileName) ResolvePstAccount(
        DeviceInventory device,
        PstFileRecord pst)
    {
        var matchingAddress = ResolveAccountAddress(device, pst.Sid, pst.ProfileName);
        var userKey = FirstNonEmpty(
            pst.UserPrincipalName,
            matchingAddress,
            $"SID:{pst.Sid}");
        var profileName = FirstNonEmpty(
            pst.ProfileName,
            ResolveProfileName(device, pst.Sid),
            "Default");
        return (userKey, profileName);
    }

    private static string? ResolveAccountAddress(
        DeviceInventory device,
        string sid,
        string? profileName)
    {
        var sidAccounts = device.MailAccounts.Where(x =>
            x.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(x.Address));
        if (!string.IsNullOrWhiteSpace(profileName))
        {
            var profileAddresses = sidAccounts
                .Where(x => string.Equals(x.ProfileName, profileName, StringComparison.OrdinalIgnoreCase))
                .Select(x => x.Address!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (profileAddresses.Length == 1)
            {
                return profileAddresses[0];
            }
            if (profileAddresses.Length > 1)
            {
                return null;
            }
        }

        var addresses = sidAccounts
            .Select(x => x.Address!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return addresses.Length == 1 ? addresses[0] : null;
    }

    private static string? ResolveProfileName(DeviceInventory device, string sid)
    {
        var profiles = device.Profiles
            .Where(x => x.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(x.ProfileName))
            .ToArray();
        return profiles.FirstOrDefault(x => x.IsDefault)?.ProfileName ??
               (profiles.Length == 1 ? profiles[0].ProfileName : null);
    }

    private void AddItem(
        ArtifactCopyJob job,
        Dictionary<string, (string UserKey, string ProfileName)> sourceOwners,
        string deviceName,
        string userKey,
        string profileName,
        string artifactType,
        string sourcePath,
        long sourceSizeBytes,
        DateTime? sourceLastWriteUtc)
    {
        var normalizedSource = sourcePath.Trim().Trim('"').Replace('/', '\\');
        var validatedDevice = RequireWithinLimit(deviceName, 64, "Source device");
        var validatedSource = RequireWithinLimit(normalizedSource, 1024, "Source path");
        ArtifactCopyPath.ToAdministrativeShare(
            validatedDevice,
            validatedSource,
            artifactType,
            _options.AllowedSourceUncRoots);
        var sourceKey = $"{deviceName}|{normalizedSource}";
        if (sourceOwners.TryGetValue(sourceKey, out var existingOwner))
        {
            if (!string.Equals(existingOwner.UserKey, userKey, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(existingOwner.ProfileName, profileName, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArtifactCopyValidationException(
                    $"Artifact ownership is ambiguous for '{normalizedSource}' on '{deviceName}'. " +
                    $"It resolves to both '{existingOwner.UserKey}/{existingOwner.ProfileName}' and '{userKey}/{profileName}'. " +
                    "Create a user-filtered plan after confirming the correct owner.");
            }

            return;
        }
        sourceOwners[sourceKey] = (userKey, profileName);

        var destinationPath = RequireWithinLimit(
            ArtifactCopyPath.BuildDestinationPath(
                job.TargetRoot,
                userKey,
                validatedDevice,
                profileName,
                artifactType,
                validatedSource),
            2048,
            "Destination path");

        job.Items.Add(new ArtifactCopyItem
        {
            DeviceName = validatedDevice,
            UserKey = Limit(userKey, 320),
            ProfileName = Limit(profileName, 256),
            ArtifactType = artifactType,
            SourcePath = validatedSource,
            SourceSizeBytes = sourceSizeBytes,
            SourceLastWriteUtc = sourceLastWriteUtc,
            DestinationPath = destinationPath,
            Status = CopyItemStatus.Planned
        });
    }

    private void ValidatePersistedItem(ArtifactCopyItem item)
    {
        var deviceName = RequireWithinLimit(item.DeviceName, 64, "Source device");
        var sourcePath = RequireWithinLimit(item.SourcePath, 1024, "Source path");
        RequireWithinLimit(item.DestinationPath, 2048, "Destination path");
        ArtifactCopyPath.ToAdministrativeShare(
            deviceName,
            sourcePath,
            item.ArtifactType,
            _options.AllowedSourceUncRoots);

        if (!ArtifactCopyPath.TryValidateAllowedRoot(
                item.DestinationPath,
                _options.AllowedTargetRoots,
                out _,
                out var destinationError))
        {
            throw new ArtifactCopyValidationException(destinationError);
        }
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.First(x => !string.IsNullOrWhiteSpace(x))!.Trim();
    }

    private static string Limit(string? value, int maxLength, string fallback = "")
    {
        var actual = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        return actual.Length <= maxLength ? actual : actual[..maxLength];
    }

    private static string RequireWithinLimit(string? value, int maxLength, string fieldName)
    {
        var actual = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(actual))
        {
            throw new ArtifactCopyValidationException($"{fieldName} is required.");
        }

        if (actual.Length > maxLength)
        {
            throw new ArtifactCopyValidationException(
                $"{fieldName} exceeds the {maxLength} character limit; the value was not truncated.");
        }

        return actual;
    }
}

public sealed class ArtifactCopyService(
    IServiceScopeFactory scopeFactory,
    IOptions<CopyOptions> options,
    ILogger<ArtifactCopyService> logger) : BackgroundService
{
    private readonly CopyOptions _options = options.Value;
    private readonly SemaphoreSlim _databaseWriteGate = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RecoverInterruptedJobsAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!_options.Enabled)
                {
                    await DelayAsync(stoppingToken);
                    continue;
                }

                var jobId = await TryClaimNextJobAsync(stoppingToken);
                if (jobId.HasValue)
                {
                    await ProcessJobSafelyAsync(jobId.Value, stoppingToken);
                    continue;
                }

                await DelayAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unhandled artifact copy polling failure");
                await DelayAsync(stoppingToken);
            }
        }
    }

    private async Task RecoverInterruptedJobsAsync(CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var interruptedIds = await db.ArtifactCopyJobs
            .AsNoTracking()
            .Where(x => x.Status == CopyJobStatus.Running)
            .Select(x => x.Id)
            .ToListAsync(cancellationToken);

        if (interruptedIds.Count == 0)
        {
            return;
        }

        await db.ArtifactCopyItems
            .Where(x =>
                interruptedIds.Contains(x.ArtifactCopyJobId) &&
                x.Status == CopyItemStatus.Copying)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, CopyItemStatus.Queued)
                    .SetProperty(x => x.ErrorMessage, "Recovered after service restart."),
                cancellationToken);
        await db.ArtifactCopyJobs
            .Where(x => interruptedIds.Contains(x.Id))
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, CopyJobStatus.Queued)
                    .SetProperty(x => x.StartedUtc, (DateTime?)null)
                    .SetProperty(x => x.CompletedUtc, (DateTime?)null)
                    .SetProperty(x => x.Notes, "Recovered after service restart."),
                cancellationToken);

        logger.LogWarning("Recovered {JobCount} interrupted artifact copy job(s)", interruptedIds.Count);
    }

    private async Task<Guid?> TryClaimNextJobAsync(CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var candidateId = await db.ArtifactCopyJobs
            .AsNoTracking()
            .Where(x => x.Status == CopyJobStatus.Queued)
            .OrderBy(x => x.CreatedUtc)
            .Select(x => (Guid?)x.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (!candidateId.HasValue)
        {
            return null;
        }

        var claimed = await db.ArtifactCopyJobs
            .Where(x => x.Id == candidateId.Value && x.Status == CopyJobStatus.Queued)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, CopyJobStatus.Running)
                    .SetProperty(x => x.StartedUtc, DateTime.UtcNow)
                    .SetProperty(x => x.CompletedUtc, (DateTime?)null),
                cancellationToken);

        return claimed == 1 ? candidateId : null;
    }

    private async Task ProcessJobSafelyAsync(Guid jobId, CancellationToken cancellationToken)
    {
        try
        {
            List<long> itemIds;
            using (var scope = scopeFactory.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
                itemIds = await db.ArtifactCopyItems
                    .AsNoTracking()
                    .Where(x =>
                        x.ArtifactCopyJobId == jobId &&
                        (x.Status == CopyItemStatus.Queued || x.Status == CopyItemStatus.Planned))
                    .OrderBy(x => x.Id)
                    .Select(x => x.Id)
                    .ToListAsync(cancellationToken);
            }

            await Parallel.ForEachAsync(
                itemIds,
                new ParallelOptions
                {
                    CancellationToken = cancellationToken,
                    MaxDegreeOfParallelism = Math.Max(1, _options.MaxParallelism)
                },
                ProcessItemAsync);

            await CompleteJobAsync(jobId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Artifact copy job {JobId} failed", jobId);
            await MarkJobFailedAsync(jobId, ex, cancellationToken);
        }
    }

    private async ValueTask ProcessItemAsync(long itemId, CancellationToken cancellationToken)
    {
        var maxAttempts = Math.Max(1, _options.MaxAttempts);
        while (true)
        {
            ArtifactCopyItem? item;
            int currentAttempt;
            await _databaseWriteGate.WaitAsync(cancellationToken);
            try
            {
                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
                item = await db.ArtifactCopyItems.SingleOrDefaultAsync(x => x.Id == itemId, cancellationToken);
                if (item is null ||
                    item.Status is CopyItemStatus.Completed or CopyItemStatus.Skipped)
                {
                    return;
                }

                if (item.Attempts >= maxAttempts)
                {
                    item.Status = CopyItemStatus.Failed;
                    item.ErrorMessage ??= $"Maximum copy attempts exhausted ({maxAttempts}).";
                    await db.SaveChangesAsync(cancellationToken);
                    return;
                }

                item.Attempts++;
                currentAttempt = item.Attempts;
                item.Status = CopyItemStatus.Copying;
                item.ErrorMessage = null;
                await db.SaveChangesAsync(cancellationToken);
            }
            finally
            {
                _databaseWriteGate.Release();
            }

            try
            {
                var result = await CopyItemFileAsync(item, cancellationToken);
                await PersistItemSuccessAsync(itemId, result, cancellationToken);
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                var finalAttempt = currentAttempt >= maxAttempts;
                await PersistItemFailureAsync(itemId, ex, finalAttempt, cancellationToken);
                if (finalAttempt)
                {
                    logger.LogError(
                        ex,
                        "Artifact copy item {ItemId} failed after {AttemptCount} attempt(s)",
                        itemId,
                        maxAttempts);
                    return;
                }

                logger.LogWarning(
                    ex,
                    "Artifact copy item {ItemId} attempt {Attempt} failed; retrying",
                    itemId,
                    currentAttempt);
            }
        }
    }

    private async Task<CopyResult> CopyItemFileAsync(
        ArtifactCopyItem item,
        CancellationToken cancellationToken)
    {
        var sourcePath = ArtifactCopyPath.ToAdministrativeShare(
            item.DeviceName,
            item.SourcePath,
            item.ArtifactType,
            _options.AllowedSourceUncRoots);
        if (!ArtifactCopyPath.TryValidateAllowedRoot(
                item.DestinationPath,
                _options.AllowedTargetRoots,
                out var destinationPath,
                out var destinationValidationError))
        {
            throw new ArtifactCopyValidationException(destinationValidationError);
        }

        var destinationDirectory = Path.GetDirectoryName(destinationPath)
            ?? throw new IOException($"Destination directory cannot be resolved: {destinationPath}");
        Directory.CreateDirectory(destinationDirectory);
        ArtifactCopyPath.ValidateNoReparsePoints(destinationDirectory);

        await using var source = OpenSourceExclusive(sourcePath);
        var sourceLength = source.Length;
        var sourceWriteUtc = File.GetLastWriteTimeUtc(sourcePath);
        if (sourceWriteUtc == DateTime.MinValue)
        {
            throw new FileNotFoundException("Source artifact does not exist.", sourcePath);
        }

        ValidateSourceAgainstSnapshot(item, sourceLength, sourceWriteUtc);

        if (File.Exists(destinationPath))
        {
            var existing = await VerifyExistingDestinationAsync(
                source,
                sourcePath,
                sourceLength,
                sourceWriteUtc,
                destinationPath,
                cancellationToken);
            if (existing.IsSame)
            {
                return new CopyResult(
                    CopyItemStatus.Skipped,
                    existing.DestinationSizeBytes,
                    existing.Sha256);
            }

            throw new IOException(
                $"Destination already exists with different content and will not be overwritten: {destinationPath}");
        }

        var partialPath = $"{destinationPath}.partial-{item.Id}";
        if (File.Exists(partialPath))
        {
            ArtifactCopyPath.ValidateNoReparsePoints(partialPath);
            File.Delete(partialPath);
        }

        string? sourceHash = null;
        try
        {
            await using (var destination = new FileStream(
                             partialPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             GetBufferSize(),
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                if (_options.VerifySha256)
                {
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[GetBufferSize()];
                    int read;
                    while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
                    {
                        await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                        hash.AppendData(buffer, 0, read);
                    }

                    sourceHash = Convert.ToHexString(hash.GetHashAndReset());
                }
                else
                {
                    await source.CopyToAsync(destination, GetBufferSize(), cancellationToken);
                }

                await destination.FlushAsync(cancellationToken);
                destination.Flush(flushToDisk: true);
            }

            EnsureOpenSourceStable(source, sourcePath, sourceLength, sourceWriteUtc);

            var partialInfo = new FileInfo(partialPath);
            if (partialInfo.Length != sourceLength)
            {
                throw new IOException(
                    $"Copied length mismatch. Source={sourceLength}, partial={partialInfo.Length}.");
            }

            if (_options.VerifySha256)
            {
                var partialHash = await ComputeSha256Async(partialPath, FileShare.Read, cancellationToken);
                if (!string.Equals(sourceHash, partialHash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException("SHA256 verification failed for the partial destination file.");
                }
            }

            ArtifactCopyPath.ValidateNoReparsePoints(destinationDirectory);
            File.Move(partialPath, destinationPath, overwrite: false);

            var destinationInfo = new FileInfo(destinationPath);
            if (destinationInfo.Length != sourceLength)
            {
                TryDelete(destinationPath);
                throw new IOException(
                    $"Destination length mismatch. Source={sourceLength}, destination={destinationInfo.Length}.");
            }

            return new CopyResult(CopyItemStatus.Completed, destinationInfo.Length, sourceHash);
        }
        catch
        {
            TryDelete(partialPath);
            throw;
        }
    }

    internal static async Task<ExistingFileResult> VerifyExistingDestinationAsync(
        FileStream source,
        string sourcePath,
        long sourceLength,
        DateTime sourceWriteUtc,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        await using var destination = new FileStream(
            destinationPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (destination.Length != sourceLength)
        {
            return new ExistingFileResult(false, destination.Length, null);
        }

        var sourceHash = await ComputeSha256Async(source, cancellationToken);
        EnsureOpenSourceStable(source, sourcePath, sourceLength, sourceWriteUtc);
        var destinationHash = await ComputeSha256Async(destination, cancellationToken);
        return new ExistingFileResult(
            string.Equals(sourceHash, destinationHash, StringComparison.OrdinalIgnoreCase),
            destination.Length,
            destinationHash);
    }

    internal static FileStream OpenSourceExclusive(string path)
    {
        try
        {
            return new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None,
                4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (IOException ex)
        {
            throw new IOException(
                $"Source artifact cannot be opened exclusively: {path}. Close Outlook before copying the PST/NK2/N2K file or copy from a VSS snapshot.",
                ex);
        }
    }

    private static async Task<string> ComputeSha256Async(
        string path,
        FileShare fileShare,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            fileShare,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    internal static async Task<string> ComputeSha256Async(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        stream.Position = 0;
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        stream.Position = 0;
        return Convert.ToHexString(hash);
    }

    private static void ValidateSourceAgainstSnapshot(
        ArtifactCopyItem item,
        long actualLength,
        DateTime actualWriteUtc)
    {
        if (item.SourceSizeBytes != actualLength)
        {
            throw new IOException(
                $"Source size changed since discovery. Snapshot={item.SourceSizeBytes}, actual={actualLength}.");
        }

        if (item.SourceLastWriteUtc.HasValue &&
            Math.Abs((item.SourceLastWriteUtc.Value - actualWriteUtc).TotalSeconds) > 2)
        {
            throw new IOException(
                $"Source modification time changed since discovery. Snapshot={item.SourceLastWriteUtc:O}, actual={actualWriteUtc:O}.");
        }
    }

    private static void EnsureOpenSourceStable(
        FileStream source,
        string sourcePath,
        long initialLength,
        DateTime initialWriteUtc)
    {
        if (source.Length != initialLength ||
            File.GetLastWriteTimeUtc(sourcePath) != initialWriteUtc)
        {
            throw new IOException("Source artifact changed while it was being copied.");
        }
    }

    private int GetBufferSize()
    {
        return Math.Clamp(_options.BufferSizeMb, 1, 64) * 1024 * 1024;
    }

    private async Task PersistItemSuccessAsync(
        long itemId,
        CopyResult result,
        CancellationToken cancellationToken)
    {
        await _databaseWriteGate.WaitAsync(cancellationToken);
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            var item = await db.ArtifactCopyItems.SingleAsync(x => x.Id == itemId, cancellationToken);
            item.Status = result.Status;
            item.DestinationSizeBytes = result.DestinationSizeBytes;
            item.Sha256 = result.Sha256;
            item.CopiedUtc = DateTime.UtcNow;
            item.ErrorMessage = null;
            await db.SaveChangesAsync(cancellationToken);
        }
        finally
        {
            _databaseWriteGate.Release();
        }
    }

    private async Task PersistItemFailureAsync(
        long itemId,
        Exception exception,
        bool finalAttempt,
        CancellationToken cancellationToken)
    {
        await _databaseWriteGate.WaitAsync(cancellationToken);
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            var item = await db.ArtifactCopyItems.SingleAsync(x => x.Id == itemId, cancellationToken);
            item.Status = finalAttempt ? CopyItemStatus.Failed : CopyItemStatus.Queued;
            item.ErrorMessage = LimitError(exception.Message);
            await db.SaveChangesAsync(cancellationToken);
        }
        finally
        {
            _databaseWriteGate.Release();
        }
    }

    private async Task CompleteJobAsync(Guid jobId, CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var job = await db.ArtifactCopyJobs
            .Include(x => x.Items)
            .SingleAsync(x => x.Id == jobId, cancellationToken);
        var failed = job.Items.Count(x => x.Status == CopyItemStatus.Failed);
        var completed = job.Items.Count(x => x.Status == CopyItemStatus.Completed);
        var skipped = job.Items.Count(x => x.Status == CopyItemStatus.Skipped);
        job.Status = failed == 0 ? CopyJobStatus.Completed : CopyJobStatus.CompletedWithErrors;
        job.CompletedUtc = DateTime.UtcNow;
        job.Notes = $"Items={job.Items.Count}; Completed={completed}; Skipped={skipped}; Failed={failed}";
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task MarkJobFailedAsync(
        Guid jobId,
        Exception exception,
        CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        await db.ArtifactCopyJobs
            .Where(x => x.Id == jobId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, CopyJobStatus.Failed)
                    .SetProperty(x => x.CompletedUtc, DateTime.UtcNow)
                    .SetProperty(x => x.Notes, LimitError(exception.Message, 2048)),
                cancellationToken);
    }

    private async Task DelayAsync(CancellationToken cancellationToken)
    {
        await Task.Delay(
            TimeSpan.FromSeconds(Math.Max(1, _options.PollingSeconds)),
            cancellationToken);
    }

    private static string LimitError(string value, int maxLength = 4096)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Preserve the original copy failure; the deterministic partial is retried later.
        }
    }

    private sealed record CopyResult(
        CopyItemStatus Status,
        long DestinationSizeBytes,
        string? Sha256);

    internal sealed record ExistingFileResult(
        bool IsSame,
        long DestinationSizeBytes,
        string? Sha256);
}

public static class ArtifactCopyPath
{
    private static readonly HashSet<string> SupportedArtifactExtensions = new(
        [".pst", ".nk2", ".n2k"],
        StringComparer.OrdinalIgnoreCase);

    private static readonly Regex HostnameOrFqdnPattern = new(
        @"\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static readonly char[] InvalidComponentCharacters =
        ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

    private static readonly HashSet<string> ReservedWindowsNames = new(
        [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        ],
        StringComparer.OrdinalIgnoreCase);

    public static string SanitizeComponent(string? value, string fallback = "Unknown")
    {
        var input = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        var builder = new StringBuilder(input.Length);
        var previousWasReplacement = false;

        foreach (var character in input)
        {
            var invalid = character < 32 || InvalidComponentCharacters.Contains(character);
            if (invalid)
            {
                if (!previousWasReplacement)
                {
                    builder.Append('_');
                    previousWasReplacement = true;
                }

                continue;
            }

            builder.Append(character);
            previousWasReplacement = false;
        }

        var sanitized = builder.ToString().Trim().TrimEnd('.', ' ');
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            sanitized = fallback;
        }

        if (ReservedWindowsNames.Contains(sanitized))
        {
            sanitized = $"_{sanitized}";
        }

        const int maxComponentLength = 120;
        return sanitized.Length <= maxComponentLength
            ? sanitized
            : sanitized[..maxComponentLength].TrimEnd('.', ' ');
    }

    public static string ToAdministrativeShare(
        string deviceName,
        string sourcePath,
        string? artifactType = null,
        IEnumerable<string>? allowedUncRoots = null)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArtifactCopyValidationException("Source path is empty.");
        }

        var normalized = sourcePath.Trim().Trim('"').Replace('/', '\\');
        ValidateNoTraversal(normalized);
        ValidateArtifactExtension(normalized, artifactType);
        if (normalized.StartsWith(@"\\", StringComparison.Ordinal))
        {
            if (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
                normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
            {
                throw new ArtifactCopyValidationException(
                    "Extended-device and Win32 device source paths are not allowed.");
            }

            var uncParts = normalized[2..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (uncParts.Length < 3)
            {
                throw new ArtifactCopyValidationException(
                    $"UNC source path must contain a server, share, and file path: {sourcePath}");
            }

            if (uncParts.Skip(2).Any(x => x.Contains(':', StringComparison.Ordinal)))
            {
                throw new ArtifactCopyValidationException(
                    $"Alternate data streams are not allowed in UNC source paths: {sourcePath}");
            }

            var normalizedUnc = Path.GetFullPath(normalized);
            var normalizedAllowedRoots = (allowedUncRoots ?? [])
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(NormalizeUncRoot)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (normalizedAllowedRoots.Length == 0)
            {
                throw new ArtifactCopyValidationException(
                    "UNC artifact sources are disabled. Configure Copy:AllowedSourceUncRoots with trusted server/share roots.");
            }

            if (!normalizedAllowedRoots.Any(root => IsWithinRoot(normalizedUnc, root)))
            {
                throw new ArtifactCopyValidationException(
                    $"UNC source is outside Copy:AllowedSourceUncRoots: {normalizedUnc}");
            }

            return normalizedUnc;
        }

        if (normalized.Length < 3 ||
            !char.IsAsciiLetter(normalized[0]) ||
            normalized[1] != ':' ||
            normalized[2] != '\\')
        {
            throw new ArtifactCopyValidationException(
                $"Source path must be UNC or an absolute local drive path: {sourcePath}");
        }

        if (string.IsNullOrWhiteSpace(deviceName) ||
            deviceName.Length > 253 ||
            !HostnameOrFqdnPattern.IsMatch(deviceName))
        {
            throw new ArtifactCopyValidationException(
                $"Source device must be a valid hostname or FQDN: {deviceName}");
        }

        var localRemainder = normalized[3..];
        if (localRemainder.Contains(':', StringComparison.Ordinal))
        {
            throw new ArtifactCopyValidationException(
                $"Alternate data streams are not allowed in source paths: {sourcePath}");
        }

        var drive = char.ToUpperInvariant(normalized[0]);
        return $@"\\{deviceName}\{drive}$\{localRemainder}";
    }

    public static string BuildDestinationPath(
        string targetRoot,
        string account,
        string deviceName,
        string? profileName,
        string artifactType,
        string sourcePath)
    {
        var root = NormalizeRoot(targetRoot);
        var originalFileName = Path.GetFileName(sourcePath.Trim().Trim('"').Replace('/', '\\'));
        if (string.IsNullOrWhiteSpace(originalFileName))
        {
            throw new ArtifactCopyValidationException($"Source file name cannot be resolved: {sourcePath}");
        }

        var extension = Path.GetExtension(originalFileName);
        var baseName = Path.GetFileNameWithoutExtension(originalFileName);
        var sourceIdentity = $"{deviceName}|{sourcePath.Trim().Trim('"').Replace('/', '\\')}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sourceIdentity)))[..12];
        var destinationFileName =
            $"{SanitizeComponent(baseName, "artifact")}_{hash}{SanitizeExtension(extension)}";

        return Path.Combine(
            root,
            SanitizeComponent(account),
            SanitizeComponent(deviceName),
            SanitizeComponent(profileName, "Default"),
            SanitizeComponent(artifactType.ToUpperInvariant()),
            destinationFileName);
    }

    public static string NormalizeRoot(string? root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArtifactCopyValidationException(
                "Target root is required. Supply TargetRoot or configure Copy:DefaultTargetRoot.");
        }

        var normalizedSeparators = root.Trim().Trim('"').Replace('/', '\\');
        if (!Path.IsPathRooted(normalizedSeparators))
        {
            throw new ArtifactCopyValidationException(
                $"Target root must be an absolute local or UNC path: {root}");
        }

        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(normalizedSeparators));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ArtifactCopyValidationException($"Target root is invalid: {ex.Message}");
        }
    }

    public static bool TryValidateAllowedRoot(
        string targetRoot,
        IEnumerable<string>? allowedRoots,
        out string normalizedTargetRoot,
        out string error)
    {
        try
        {
            normalizedTargetRoot = NormalizeRoot(targetRoot);
        }
        catch (ArtifactCopyValidationException ex)
        {
            normalizedTargetRoot = string.Empty;
            error = ex.Message;
            return false;
        }

        var normalizedAllowedRoots = new List<string>();
        foreach (var allowedRoot in allowedRoots ?? [])
        {
            if (string.IsNullOrWhiteSpace(allowedRoot))
            {
                continue;
            }

            try
            {
                normalizedAllowedRoots.Add(NormalizeRoot(allowedRoot));
            }
            catch (ArtifactCopyValidationException)
            {
                // Invalid configured roots are ignored; execution remains fail-closed.
            }
        }

        if (normalizedAllowedRoots.Count == 0)
        {
            error = "Copy:AllowedTargetRoots contains no valid absolute roots.";
            return false;
        }

        var targetRootForComparison = normalizedTargetRoot;
        var matchedRoot = normalizedAllowedRoots.FirstOrDefault(allowedRoot =>
            IsWithinRoot(targetRootForComparison, allowedRoot));
        if (matchedRoot is null)
        {
            error = $"Target root is outside Copy:AllowedTargetRoots: {normalizedTargetRoot}";
            return false;
        }

        try
        {
            ValidateNoReparsePoints(normalizedTargetRoot);
        }
        catch (ArtifactCopyValidationException ex)
        {
            error = ex.Message;
            return false;
        }

        error = string.Empty;
        return true;
    }

    public static void ValidateNoReparsePoints(string path)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ArtifactCopyValidationException($"Path is invalid: {ex.Message}");
        }

        var pathRoot = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(pathRoot))
        {
            throw new ArtifactCopyValidationException($"Path root cannot be resolved: {path}");
        }

        var current = pathRoot;
        EnsureExistingPathIsNotReparsePoint(current);
        var relativePath = fullPath[pathRoot.Length..];
        foreach (var component in relativePath.Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if (!EnsureExistingPathIsNotReparsePoint(current))
            {
                break;
            }
        }
    }

    private static string SanitizeExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
        {
            return string.Empty;
        }

        var sanitized = new string(extension
            .Where(x => x == '.' || char.IsAsciiLetterOrDigit(x))
            .ToArray());
        return sanitized.StartsWith('.') ? sanitized : $".{sanitized}";
    }

    private static void ValidateArtifactExtension(string sourcePath, string? artifactType)
    {
        var extension = Path.GetExtension(sourcePath);
        if (!SupportedArtifactExtensions.Contains(extension))
        {
            throw new ArtifactCopyValidationException(
                $"Source extension must be PST, NK2, or N2K: {sourcePath}");
        }

        if (string.IsNullOrWhiteSpace(artifactType))
        {
            return;
        }

        var expectedExtension = $".{artifactType.Trim().TrimStart('.')}";
        if (!SupportedArtifactExtensions.Contains(expectedExtension) ||
            !extension.Equals(expectedExtension, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArtifactCopyValidationException(
                $"Source extension '{extension}' does not match artifact type '{artifactType}'.");
        }
    }

    private static string NormalizeUncRoot(string root)
    {
        var normalized = root.Trim().Trim('"').Replace('/', '\\');
        ValidateNoTraversal(normalized);
        if (!normalized.StartsWith(@"\\", StringComparison.Ordinal) ||
            normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            throw new ArtifactCopyValidationException(
                $"Allowed UNC source root must be a standard UNC server/share path: {root}");
        }

        var parts = normalized[2..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || parts.Skip(2).Any(x => x.Contains(':', StringComparison.Ordinal)))
        {
            throw new ArtifactCopyValidationException(
                $"Allowed UNC source root is invalid: {root}");
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(normalized));
    }

    private static bool IsWithinRoot(string candidate, string root)
    {
        var prefix = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        return candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool EnsureExistingPathIsNotReparsePoint(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new ArtifactCopyValidationException(
                    $"Destination path contains a reparse point, junction, or symbolic link: {path}");
            }

            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
        catch (ArtifactCopyValidationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ArtifactCopyValidationException(
                $"Destination path cannot be safely inspected for reparse points: {path}. {ex.Message}");
        }
    }

    private static void ValidateNoTraversal(string path)
    {
        if (path
            .Split('\\', StringSplitOptions.RemoveEmptyEntries)
            .Any(segment => segment is "." or ".."))
        {
            throw new ArtifactCopyValidationException(
                $"Path traversal segments are not allowed: {path}");
        }
    }
}
