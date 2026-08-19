using System.DirectoryServices;
using System.IO.Enumeration;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("O365AuditTool.Tests")]

namespace O365AuditTool.Services;

public record DeviceTarget(string Name, string? Ou = null, string? Site = null);

public interface IDeviceTargetProvider
{
    Task<IReadOnlyList<DeviceTarget>> GetTargetsAsync(string? ouFilter, string? siteFilter, CancellationToken cancellationToken);
}

public class ActiveDirectoryTargetProvider : IDeviceTargetProvider
{
    private const int ExclusionSampleLimit = 10;
    private const int DomainControllerPrimaryGroupId = 516;
    private const int ReadOnlyDomainControllerPrimaryGroupId = 521;

    private const string ReasonDeviceName = "DeviceName";
    private const string ReasonExcludedOu = "ExcludedOu";
    private const string ReasonDomainController = "DomainController";
    private const string ReasonServerOperatingSystem = "ServerOperatingSystem";
    private const string ReasonUnknownOperatingSystem = "UnknownOperatingSystem";

    private static readonly string[] ReasonOrder =
    [
        ReasonDeviceName,
        ReasonExcludedOu,
        ReasonDomainController,
        ReasonServerOperatingSystem,
        ReasonUnknownOperatingSystem
    ];

    private readonly IConfiguration _configuration;
    private readonly ILogger<ActiveDirectoryTargetProvider> _logger;
    private readonly IActiveDirectoryComputerSource _computerSource;

    public ActiveDirectoryTargetProvider(
        IConfiguration configuration,
        ILogger<ActiveDirectoryTargetProvider> logger)
        : this(configuration, logger, new DirectoryServicesComputerSource())
    {
    }

    internal ActiveDirectoryTargetProvider(
        IConfiguration configuration,
        ILogger<ActiveDirectoryTargetProvider> logger,
        IActiveDirectoryComputerSource computerSource)
    {
        _configuration = configuration;
        _logger = logger;
        _computerSource = computerSource;
    }

    public Task<IReadOnlyList<DeviceTarget>> GetTargetsAsync(
        string? ouFilter,
        string? siteFilter,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<ActiveDirectoryComputer> computers;
        try
        {
            computers = _computerSource.GetComputers(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ActiveDirectoryDiscoveryException ex)
        {
            var fallback = GetExplicitFallbackTargets();
            if (fallback.Count == 0)
            {
                throw new InvalidOperationException(
                    "Active Directory target discovery failed and no explicit fallback targets are configured.",
                    ex);
            }

            _logger.LogWarning(
                ex,
                "AD target discovery failed. Using {TargetCount} explicitly configured fallback target(s); OU/site metadata cannot be verified.",
                fallback.Count);
            return Task.FromResult(fallback);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var normalizedOuFilter = NormalizeFilter(ouFilter);
        var normalizedSiteFilter = NormalizeFilter(siteFilter);
        var inactiveDays = Math.Max(0, _configuration.GetValue("Collector:ExcludeComputersInactiveDays", 120));
        var activeCutoffUtc = DateTime.UtcNow.AddDays(-inactiveDays);

        var candidates = computers
            .Where(x => x.Enabled)
            .Where(x => inactiveDays == 0 || x.LastLogonUtc is null || x.LastLogonUtc >= activeCutoffUtc)
            .Where(x => normalizedOuFilter is null || MatchesOu(x.DistinguishedName, normalizedOuFilter))
            .Where(x => normalizedSiteFilter is null ||
                        string.Equals(x.Site?.Trim(), normalizedSiteFilter, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        var targets = NormalizeTargets(
            ApplyExclusions(candidates, ReadExclusionPolicy())
                .Select(x => new DeviceTarget(
                    x.Name.Trim(),
                    GetParentDistinguishedName(x.DistinguishedName),
                    NormalizeFilter(x.Site))));

        if (targets.Count == 0 && (normalizedOuFilter is not null || normalizedSiteFilter is not null))
        {
            _logger.LogWarning(
                "AD discovery returned no enabled computers for OU filter {OuFilter} and site filter {SiteFilter}. No fallback will be used for a zero-result scope.",
                normalizedOuFilter,
                normalizedSiteFilter);
        }

        return Task.FromResult(targets);
    }

    /// <summary>
    /// Drops objects the collector can never succeed on, before they reach PsExec. Measured on
    /// nbr.local (2026-08): the domain-root OU scope fed Windows Servers, the DC itself and
    /// domain-joined Synology/NAS appliances into the nightly run, where each one held a parallel
    /// slot until it timed out and was then reported as an offline workstation.
    /// </summary>
    private IReadOnlyList<ActiveDirectoryComputer> ApplyExclusions(
        IReadOnlyList<ActiveDirectoryComputer> candidates,
        ExclusionPolicy policy)
    {
        var retained = new List<ActiveDirectoryComputer>(candidates.Count);
        var countsByReason = new Dictionary<string, int>(StringComparer.Ordinal);
        var samplesByReason = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var matchedPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            var (reason, pattern) = Classify(candidate, policy);
            if (reason is null)
            {
                retained.Add(candidate);
                continue;
            }

            countsByReason[reason] = countsByReason.GetValueOrDefault(reason) + 1;
            if (pattern is not null)
            {
                matchedPatterns.Add(pattern);
            }

            if (!samplesByReason.TryGetValue(reason, out var samples))
            {
                samples = new List<string>(ExclusionSampleLimit);
                samplesByReason[reason] = samples;
            }

            if (samples.Count < ExclusionSampleLimit)
            {
                samples.Add(candidate.Name.Trim());
            }
        }

        // A silent exclusion reads as "we covered everything", so every scan states what it dropped,
        // why, and which configured pattern matched nothing (a typo there silently scans servers again).
        var unmatchedPatterns = policy.DeviceNamePatterns
            .Concat(policy.ExcludedOus)
            .Where(pattern => !matchedPatterns.Contains(pattern))
            .ToArray();

        _logger.LogInformation(
            "AD targeting: {CandidateCount} candidate(s) in scope, {ExcludedCount} excluded, {TargetCount} target(s). " +
            "Exclusions by reason: {ExclusionCounts}. Samples: {ExclusionSamples}. Patterns matching nothing: {UnmatchedPatterns}.",
            candidates.Count,
            candidates.Count - retained.Count,
            retained.Count,
            FormatCounts(countsByReason),
            FormatList(BuildExclusionSamples(samplesByReason)),
            FormatList(unmatchedPatterns));

        return retained;
    }

    /// <summary>
    /// Explicitly configured rules are evaluated before the attribute rules so a device is always
    /// credited to the pattern that matches it; otherwise an attribute rule would claim the device
    /// and the operator's own pattern would be reported as matching nothing.
    /// </summary>
    private static (string? Reason, string? Pattern) Classify(ActiveDirectoryComputer computer, ExclusionPolicy policy)
    {
        var name = computer.Name.Trim();

        var namePattern = policy.DeviceNamePatterns.FirstOrDefault(pattern => MatchesNamePattern(name, pattern));
        if (namePattern is not null)
        {
            return (ReasonDeviceName, namePattern);
        }

        var excludedOu = policy.ExcludedOus.FirstOrDefault(ou => MatchesOu(computer.DistinguishedName, ou));
        if (excludedOu is not null)
        {
            return (ReasonExcludedOu, excludedOu);
        }

        if (policy.ExcludeDomainControllers &&
            computer.PrimaryGroupId is DomainControllerPrimaryGroupId or ReadOnlyDomainControllerPrimaryGroupId)
        {
            return (ReasonDomainController, null);
        }

        if (policy.ExcludeServerOperatingSystems &&
            computer.OperatingSystem?.Contains("Server", StringComparison.OrdinalIgnoreCase) == true)
        {
            return (ReasonServerOperatingSystem, null);
        }

        // Domain-joined appliances (NASCLUSTER, NBRSYNOLOGY, NBR_DS1825PLUS on nbr.local) carry an
        // empty operatingSystem and can never run the collector.
        if (policy.ExcludeUnknownOperatingSystem && string.IsNullOrWhiteSpace(computer.OperatingSystem))
        {
            return (ReasonUnknownOperatingSystem, null);
        }

        return (null, null);
    }

    // CollectorOptions is the single source of truth for defaults. Repeating literals here once
    // already produced a silent disagreement between the two readers of the same key, so the
    // defaults are taken from a fresh CollectorOptions instance instead of being written twice.
    private static readonly CollectorOptions DefaultCollectorOptions = new();

    private ExclusionPolicy ReadExclusionPolicy() => new(
        ReadConfiguredPatterns("Collector:ExcludeDeviceNames"),
        ReadConfiguredPatterns("Collector:ExcludeOus"),
        _configuration.GetValue("Collector:ExcludeServerOperatingSystems", DefaultCollectorOptions.ExcludeServerOperatingSystems),
        _configuration.GetValue("Collector:ExcludeDomainControllers", DefaultCollectorOptions.ExcludeDomainControllers),
        // A blank operatingSystem is a hint rather than proof, so this rule is the one most likely
        // to drop a real workstation (joined but never booted). It defaults to OFF in
        // CollectorOptions; the per-reason summary above keeps any drop visible in the scan log.
        _configuration.GetValue("Collector:ExcludeUnknownOperatingSystem", DefaultCollectorOptions.ExcludeUnknownOperatingSystem));

    private string[] ReadConfiguredPatterns(string key) =>
        (_configuration.GetSection(key).Get<string[]>() ?? [])
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .ToArray();

    /// <summary>
    /// Anchored, case-insensitive <c>*</c>/<c>?</c> matching. The framework matcher is used instead of a
    /// translated regular expression because it anchors both ends (so <c>NAS*</c> cannot match
    /// <c>XNASY</c>) and cannot backtrack on an operator-supplied pattern.
    /// </summary>
    internal static bool MatchesNamePattern(string? name, string? pattern)
    {
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        return FileSystemName.MatchesSimpleExpression(pattern.Trim(), name.Trim(), ignoreCase: true);
    }

    private static IReadOnlyList<string> BuildExclusionSamples(IReadOnlyDictionary<string, List<string>> samplesByReason)
    {
        // Round-robin across reasons so a single high-count reason cannot crowd the others out of the
        // sample; the counts already carry the magnitude, the samples only have to identify the class.
        var samples = new List<string>(ExclusionSampleLimit);
        for (var depth = 0; samples.Count < ExclusionSampleLimit; depth++)
        {
            var added = false;
            foreach (var reason in ReasonOrder)
            {
                if (!samplesByReason.TryGetValue(reason, out var names) || depth >= names.Count)
                {
                    continue;
                }

                samples.Add($"{names[depth]} ({reason})");
                added = true;
                if (samples.Count == ExclusionSampleLimit)
                {
                    break;
                }
            }

            if (!added)
            {
                break;
            }
        }

        return samples;
    }

    private static string FormatCounts(IReadOnlyDictionary<string, int> countsByReason) =>
        countsByReason.Count == 0
            ? "none"
            : string.Join(", ", ReasonOrder
                .Where(countsByReason.ContainsKey)
                .Select(reason => $"{reason}={countsByReason[reason]}"));

    private static string FormatList(IReadOnlyCollection<string> values) =>
        values.Count == 0 ? "none" : string.Join(", ", values);

    internal static bool MatchesOu(string? distinguishedName, string ouFilter)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName) || string.IsNullOrWhiteSpace(ouFilter))
        {
            return false;
        }

        var normalizedFilter = ouFilter.Trim();
        if (normalizedFilter.Contains(','))
        {
            return distinguishedName.Equals(normalizedFilter, StringComparison.OrdinalIgnoreCase) ||
                   distinguishedName.EndsWith($",{normalizedFilter}", StringComparison.OrdinalIgnoreCase);
        }

        var ouComponent = normalizedFilter.StartsWith("OU=", StringComparison.OrdinalIgnoreCase)
            ? normalizedFilter
            : $"OU={normalizedFilter}";

        return distinguishedName
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Any(component => component.Equals(ouComponent, StringComparison.OrdinalIgnoreCase));
    }

    internal static string? GetParentDistinguishedName(string? distinguishedName)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return null;
        }

        for (var index = 0; index < distinguishedName.Length; index++)
        {
            if (distinguishedName[index] != ',')
            {
                continue;
            }

            var escapeCount = 0;
            for (var previous = index - 1; previous >= 0 && distinguishedName[previous] == '\\'; previous--)
            {
                escapeCount++;
            }

            if (escapeCount % 2 == 0)
            {
                return NormalizeFilter(distinguishedName[(index + 1)..]);
            }
        }

        return null;
    }

    private IReadOnlyList<DeviceTarget> GetExplicitFallbackTargets()
    {
        var configuredTargets = _configuration
            .GetSection("Collector:FallbackTargets")
            .Get<string[]>() ?? [];
        var namePatterns = ReadConfiguredPatterns("Collector:ExcludeDeviceNames");

        var kept = new List<DeviceTarget>(configuredTargets.Length);
        var dropped = new List<string>();
        foreach (var configuredTarget in configuredTargets)
        {
            var name = configuredTarget?.Trim();
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }

            // Only the name rule is evaluable here: this path runs because AD is unreachable, so
            // operatingSystem/primaryGroupID/DN are unknown. Applying the attribute rules would drop
            // every fallback target as "unknown OS" at exactly the moment discovery already failed.
            if (namePatterns.Any(pattern => MatchesNamePattern(name, pattern)))
            {
                dropped.Add(name);
                continue;
            }

            kept.Add(new DeviceTarget(name));
        }

        if (dropped.Count > 0)
        {
            _logger.LogWarning(
                "{DroppedCount} configured fallback target(s) match Collector:ExcludeDeviceNames and will not be scanned: {DroppedTargets}.",
                dropped.Count,
                FormatList(dropped));
        }

        return NormalizeTargets(kept);
    }

    private static IReadOnlyList<DeviceTarget> NormalizeTargets(IEnumerable<DeviceTarget> targets)
    {
        return targets
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Name, StringComparer.Ordinal)
            .ThenBy(x => x.Ou ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Site ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Name, StringComparer.Ordinal)
            .ToArray();
    }

    private static string? NormalizeFilter(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record ExclusionPolicy(
        string[] DeviceNamePatterns,
        string[] ExcludedOus,
        bool ExcludeServerOperatingSystems,
        bool ExcludeDomainControllers,
        bool ExcludeUnknownOperatingSystem);
}

internal sealed record ActiveDirectoryComputer(
    string Name,
    string? DistinguishedName,
    string? Site,
    bool Enabled = true,
    DateTime? LastLogonUtc = null,
    string? OperatingSystem = null,
    int? PrimaryGroupId = null);

internal interface IActiveDirectoryComputerSource
{
    IReadOnlyList<ActiveDirectoryComputer> GetComputers(CancellationToken cancellationToken);
}

internal sealed class DirectoryServicesComputerSource : IActiveDirectoryComputerSource
{
    private static readonly TimeSpan SearchTimeout = TimeSpan.FromSeconds(15);

    internal const string ComputerFilter =
        "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    public IReadOnlyList<ActiveDirectoryComputer> GetComputers(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var root = new DirectoryEntry();
            using var searcher = new DirectorySearcher(root)
            {
                Filter = ComputerFilter,
                PageSize = 1000,
                ClientTimeout = SearchTimeout,
                ServerTimeLimit = SearchTimeout,
                ReferralChasing = ReferralChasingOption.None
            };

            searcher.PropertiesToLoad.Add("name");
            searcher.PropertiesToLoad.Add("distinguishedName");
            searcher.PropertiesToLoad.Add("msDS-SiteName");
            searcher.PropertiesToLoad.Add("userAccountControl");
            searcher.PropertiesToLoad.Add("lastLogonTimestamp");
            searcher.PropertiesToLoad.Add("operatingSystem");
            searcher.PropertiesToLoad.Add("primaryGroupID");

            using var results = searcher.FindAll();
            var computers = new List<ActiveDirectoryComputer>(results.Count);
            foreach (SearchResult result in results)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var name = GetFirstString(result, "name");
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                var userAccountControl = GetFirstInt32(result, "userAccountControl");
                var enabled = userAccountControl is null || (userAccountControl.Value & 0x2) == 0;
                computers.Add(new ActiveDirectoryComputer(
                    name,
                    GetFirstString(result, "distinguishedName"),
                    GetFirstString(result, "msDS-SiteName"),
                    enabled,
                    GetFileTimeUtc(result, "lastLogonTimestamp"),
                    GetFirstString(result, "operatingSystem"),
                    GetFirstInt32(result, "primaryGroupID")));
            }

            return computers;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not AccessViolationException)
        {
            throw new ActiveDirectoryDiscoveryException("Active Directory computer discovery failed.", ex);
        }
    }

    private static string? GetFirstString(SearchResult result, string propertyName) =>
        result.Properties[propertyName]?.Count > 0
            ? result.Properties[propertyName][0]?.ToString()
            : null;

    private static int? GetFirstInt32(SearchResult result, string propertyName)
    {
        var value = result.Properties[propertyName]?.Count > 0
            ? result.Properties[propertyName][0]
            : null;
        return value is null ? null : Convert.ToInt32(value);
    }

    private static DateTime? GetFileTimeUtc(SearchResult result, string propertyName)
    {
        var value = result.Properties[propertyName]?.Count > 0
            ? result.Properties[propertyName][0]
            : null;
        if (value is null)
        {
            return null;
        }

        try
        {
            var fileTime = Convert.ToInt64(value);
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime) : null;
        }
        catch (Exception) when (value is not null)
        {
            return null;
        }
    }
}

internal sealed class ActiveDirectoryDiscoveryException(string message, Exception innerException)
    : Exception(message, innerException);
