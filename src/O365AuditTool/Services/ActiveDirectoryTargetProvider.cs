using System.DirectoryServices;
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

        var targets = NormalizeTargets(
            computers
                .Where(x => x.Enabled)
                .Where(x => inactiveDays == 0 || x.LastLogonUtc is null || x.LastLogonUtc >= activeCutoffUtc)
                .Where(x => normalizedOuFilter is null || MatchesOu(x.DistinguishedName, normalizedOuFilter))
                .Where(x => normalizedSiteFilter is null ||
                            string.Equals(x.Site?.Trim(), normalizedSiteFilter, StringComparison.OrdinalIgnoreCase))
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

        return NormalizeTargets(configuredTargets.Select(x => new DeviceTarget(x.Trim())));
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
}

internal sealed record ActiveDirectoryComputer(
    string Name,
    string? DistinguishedName,
    string? Site,
    bool Enabled = true,
    DateTime? LastLogonUtc = null);

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
                    GetFileTimeUtc(result, "lastLogonTimestamp")));
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
