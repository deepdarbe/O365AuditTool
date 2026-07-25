using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using O365AuditTool.Data;
using O365AuditTool.Models;

namespace O365AuditTool.Services;

public interface IArtifactCopyPlanService
{
    Task<ArtifactCopyJob> CreatePlanAsync(
        CreateCopyPlanRequest request,
        string requestedBy,
        CancellationToken cancellationToken);

    Task<ArtifactCopyJob?> GetPlanAsync(Guid id, CancellationToken cancellationToken);

    Task<List<ArtifactCopyJob>> ListPlansAsync(int take, CancellationToken cancellationToken);

    Task<ArtifactCopyJob?> QueuePlanAsync(Guid id, CancellationToken cancellationToken);
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
        var normalizedTargetRoot = ArtifactCopyPath.NormalizeRoot(targetRoot);
        var deviceFilter = BuildFilter(request.Devices);
        var userFilter = BuildFilter(request.Users);
        var artifactTypes = NormalizeArtifactTypes(request.ArtifactTypes);

        var latestUsableIds = await db.Devices
            .AsNoTracking()
            .Where(x =>
                x.Status == DeviceScanStatus.Success ||
                (x.Status == DeviceScanStatus.Error && x.RawPayloadJson != "{}"))
            .GroupBy(x => x.DeviceName)
            .Select(group => group
                .OrderByDescending(x => x.CollectedUtc)
                .ThenByDescending(x => x.Id)
                .Select(x => x.Id)
                .First())
            .ToListAsync(cancellationToken);

        var snapshots = await db.Devices
            .AsNoTracking()
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
            TargetRoot = Limit(normalizedTargetRoot, 1024),
            Status = CopyJobStatus.Planned
        };

        var sourceKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
                        sourceKeys,
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
                    ResolveAccountAddress(device, legacy.Sid),
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
                    sourceKeys,
                    device.DeviceName,
                    userKey,
                    profileName,
                    legacy.ArtifactType.ToUpperInvariant(),
                    legacy.Path,
                    legacy.SizeBytes,
                    legacy.LastWriteUtc);
            }
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

    public async Task<ArtifactCopyJob?> QueuePlanAsync(Guid id, CancellationToken cancellationToken)
    {
        var job = await db.ArtifactCopyJobs
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

        if (!ArtifactCopyPath.TryValidateAllowedRoot(
                job.TargetRoot,
                _options.AllowedTargetRoots,
                out var normalizedTargetRoot,
                out var validationError))
        {
            throw new ArtifactCopyValidationException(validationError);
        }

        job.TargetRoot = Limit(normalizedTargetRoot, 1024);
        job.Status = CopyJobStatus.Queued;
        job.StartedUtc = null;
        job.CompletedUtc = null;
        foreach (var item in job.Items)
        {
            item.Status = CopyItemStatus.Queued;
            item.ErrorMessage = null;
        }

        await db.SaveChangesAsync(cancellationToken);
        return job;
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
        var matchingAccount = device.MailAccounts.FirstOrDefault(x =>
            x.Sid.Equals(pst.Sid, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(x.Address));
        var userKey = FirstNonEmpty(
            pst.UserPrincipalName,
            matchingAccount?.Address,
            $"SID:{pst.Sid}");
        var profileName = FirstNonEmpty(
            matchingAccount?.ProfileName,
            ResolveProfileName(device, pst.Sid),
            "Default");
        return (userKey, profileName);
    }

    private static string? ResolveAccountAddress(DeviceInventory device, string sid)
    {
        return device.MailAccounts.FirstOrDefault(x =>
            x.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(x.Address))?.Address;
    }

    private static string? ResolveProfileName(DeviceInventory device, string sid)
    {
        return device.Profiles.FirstOrDefault(x =>
            x.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(x.ProfileName))?.ProfileName;
    }

    private static void AddItem(
        ArtifactCopyJob job,
        HashSet<string> sourceKeys,
        string deviceName,
        string userKey,
        string profileName,
        string artifactType,
        string sourcePath,
        long sourceSizeBytes,
        DateTime? sourceLastWriteUtc)
    {
        var normalizedSource = sourcePath.Trim().Trim('"').Replace('/', '\\');
        var sourceKey = $"{deviceName}|{normalizedSource}";
        if (!sourceKeys.Add(sourceKey))
        {
            return;
        }

        job.Items.Add(new ArtifactCopyItem
        {
            DeviceName = Limit(deviceName, 64),
            UserKey = Limit(userKey, 320),
            ProfileName = Limit(profileName, 256),
            ArtifactType = artifactType,
            SourcePath = Limit(normalizedSource, 1024),
            SourceSizeBytes = sourceSizeBytes,
            SourceLastWriteUtc = sourceLastWriteUtc,
            DestinationPath = Limit(
                ArtifactCopyPath.BuildDestinationPath(
                    job.TargetRoot,
                    userKey,
                    deviceName,
                    profileName,
                    artifactType,
                    normalizedSource),
                2048),
            Status = CopyItemStatus.Planned
        });
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
        var sourcePath = ArtifactCopyPath.ToAdministrativeShare(item.DeviceName, item.SourcePath);
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

        var sourceBefore = new FileInfo(sourcePath);
        if (!sourceBefore.Exists)
        {
            throw new FileNotFoundException("Source artifact does not exist.", sourcePath);
        }

        sourceBefore.Refresh();
        var sourceLength = sourceBefore.Length;
        var sourceWriteUtc = sourceBefore.LastWriteTimeUtc;
        ValidateSourceAgainstSnapshot(item, sourceLength, sourceWriteUtc);

        if (File.Exists(destinationPath))
        {
            var existing = await VerifyExistingDestinationAsync(
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
            File.Delete(partialPath);
        }

        string? sourceHash = null;
        try
        {
            await using (var source = OpenSource(sourcePath))
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
            }

            var sourceAfter = new FileInfo(sourcePath);
            sourceAfter.Refresh();
            EnsureSourceStable(sourceLength, sourceWriteUtc, sourceAfter);

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

    private async Task<ExistingFileResult> VerifyExistingDestinationAsync(
        string sourcePath,
        long sourceLength,
        DateTime sourceWriteUtc,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        var destinationInfo = new FileInfo(destinationPath);
        if (destinationInfo.Length != sourceLength)
        {
            return new ExistingFileResult(false, destinationInfo.Length, null);
        }

        if (!_options.VerifySha256)
        {
            var sourceAfterLengthCheck = new FileInfo(sourcePath);
            sourceAfterLengthCheck.Refresh();
            EnsureSourceStable(sourceLength, sourceWriteUtc, sourceAfterLengthCheck);
            return new ExistingFileResult(true, destinationInfo.Length, null);
        }

        var sourceHash = await ComputeSha256Async(
            sourcePath,
            FileShare.ReadWrite | FileShare.Delete,
            cancellationToken);
        var sourceAfterHash = new FileInfo(sourcePath);
        sourceAfterHash.Refresh();
        EnsureSourceStable(sourceLength, sourceWriteUtc, sourceAfterHash);
        var destinationHash = await ComputeSha256Async(destinationPath, FileShare.Read, cancellationToken);
        return new ExistingFileResult(
            string.Equals(sourceHash, destinationHash, StringComparison.OrdinalIgnoreCase),
            destinationInfo.Length,
            destinationHash);
    }

    private static FileStream OpenSource(string path)
    {
        return new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
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

    private static void EnsureSourceStable(
        long initialLength,
        DateTime initialWriteUtc,
        FileInfo sourceAfter)
    {
        if (!sourceAfter.Exists ||
            sourceAfter.Length != initialLength ||
            sourceAfter.LastWriteTimeUtc != initialWriteUtc)
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

    private sealed record ExistingFileResult(
        bool IsSame,
        long DestinationSizeBytes,
        string? Sha256);
}

public static class ArtifactCopyPath
{
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

    public static string ToAdministrativeShare(string deviceName, string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArtifactCopyValidationException("Source path is empty.");
        }

        var normalized = sourcePath.Trim().Trim('"').Replace('/', '\\');
        ValidateNoTraversal(normalized);
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

            return normalized;
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
        var isAllowed = normalizedAllowedRoots.Any(allowedRoot =>
        {
            var allowedPrefix = Path.EndsInDirectorySeparator(allowedRoot)
                ? allowedRoot
                : allowedRoot + Path.DirectorySeparatorChar;
            return targetRootForComparison.Equals(allowedRoot, StringComparison.OrdinalIgnoreCase) ||
                   targetRootForComparison.StartsWith(
                       allowedPrefix,
                       StringComparison.OrdinalIgnoreCase);
        });

        error = isAllowed
            ? string.Empty
            : $"Target root is outside Copy:AllowedTargetRoots: {normalizedTargetRoot}";
        return isAllowed;
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
