using Microsoft.Extensions.Logging.Abstractions;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace O365AuditTool.Services;

public sealed record OrganizationalUnitScope(
    string Name,
    string DistinguishedName,
    string DisplayName,
    string? ParentDistinguishedName,
    int Depth);

public sealed record ActiveDirectorySiteScope(string Name, string DistinguishedName);

public sealed record ActiveDirectoryStructure(
    string DomainDistinguishedName,
    IReadOnlyList<OrganizationalUnitScope> OrganizationalUnits,
    IReadOnlyList<ActiveDirectorySiteScope> Sites,
    IReadOnlyList<string> Warnings);

public interface IActiveDirectoryStructureProvider
{
    Task<ActiveDirectoryStructure> GetStructureAsync(CancellationToken cancellationToken);
}

public sealed class ActiveDirectoryStructureProvider : IActiveDirectoryStructureProvider
{
    private static readonly TimeSpan DiscoveryDeadline = TimeSpan.FromSeconds(30);
    private readonly IActiveDirectoryStructureSource _source;
    private readonly ILogger<ActiveDirectoryStructureProvider> _logger;
    private readonly SemaphoreSlim _discoveryGate = new(1, 1);

    public ActiveDirectoryStructureProvider(ILogger<ActiveDirectoryStructureProvider> logger)
        : this(
            new FallbackActiveDirectoryStructureSource(
                new DirectoryServicesStructureSource(),
                new ComputerDerivedStructureSource(new DirectoryServicesComputerSource())),
            logger)
    {
    }

    internal ActiveDirectoryStructureProvider(IActiveDirectoryStructureSource source)
        : this(source, NullLogger<ActiveDirectoryStructureProvider>.Instance)
    {
    }

    internal ActiveDirectoryStructureProvider(
        IActiveDirectoryStructureSource source,
        ILogger<ActiveDirectoryStructureProvider> logger)
    {
        _source = source;
        _logger = logger;
    }

    public async Task<ActiveDirectoryStructure> GetStructureAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await _discoveryGate.WaitAsync(DiscoveryDeadline, cancellationToken))
        {
            throw new ActiveDirectoryStructureDiscoveryException(
                "A previous Active Directory structure discovery call is still running.",
                new TimeoutException("Active Directory discovery gate timed out."));
        }

        ActiveDirectoryStructureData raw;
        var releaseGate = true;
        var discoveryTask = Task.Run(() => _source.GetStructure(cancellationToken), CancellationToken.None);
        try
        {
            raw = await discoveryTask.WaitAsync(DiscoveryDeadline, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (!discoveryTask.IsCompleted)
            {
                releaseGate = false;
                _ = discoveryTask.ContinueWith(
                    _ => _discoveryGate.Release(),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
            throw;
        }
        catch (TimeoutException ex)
        {
            releaseGate = false;
            _ = discoveryTask.ContinueWith(
                _ => _discoveryGate.Release(),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw new ActiveDirectoryStructureDiscoveryException(
                "Active Directory structure discovery exceeded its deadline.",
                ex);
        }
        finally
        {
            if (releaseGate)
            {
                _discoveryGate.Release();
            }
        }

        var ouByDn = raw.OrganizationalUnits
            .Where(x => !string.IsNullOrWhiteSpace(x.Name) && !string.IsNullOrWhiteSpace(x.DistinguishedName))
            .GroupBy(x => x.DistinguishedName.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToDictionary(x => x.DistinguishedName.Trim(), StringComparer.OrdinalIgnoreCase);

        var organizationalUnits = ouByDn.Values
            .Select(ou => BuildScope(ou, ouByDn))
            .OrderBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var sites = raw.Sites
            .Where(x => !string.IsNullOrWhiteSpace(x.Name) && !string.IsNullOrWhiteSpace(x.DistinguishedName))
            .GroupBy(x => x.Name.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ActiveDirectorySiteScope(x.Name.Trim(), x.DistinguishedName.Trim()))
            .ToArray();

        foreach (var warning in raw.Warnings)
        {
            _logger.LogWarning("Active Directory structure discovery warning: {Warning}", warning);
        }

        return new ActiveDirectoryStructure(
            raw.DomainDistinguishedName.Trim(),
            organizationalUnits,
            sites,
            raw.Warnings);
    }

    private static OrganizationalUnitScope BuildScope(
        ActiveDirectoryOrganizationalUnit organizationalUnit,
        IReadOnlyDictionary<string, ActiveDirectoryOrganizationalUnit> ouByDn)
    {
        var labels = new Stack<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = organizationalUnit;
        while (visited.Add(current.DistinguishedName))
        {
            labels.Push(current.Name.Trim());
            var parentDn = ActiveDirectoryTargetProvider.GetParentDistinguishedName(current.DistinguishedName);
            if (parentDn is null || !ouByDn.TryGetValue(parentDn, out current))
            {
                break;
            }
        }

        var parentDistinguishedName = ActiveDirectoryTargetProvider.GetParentDistinguishedName(
            organizationalUnit.DistinguishedName);
        return new OrganizationalUnitScope(
            organizationalUnit.Name.Trim(),
            organizationalUnit.DistinguishedName.Trim(),
            string.Join(" / ", labels),
            parentDistinguishedName,
            labels.Count);
    }
}

internal sealed record ActiveDirectoryOrganizationalUnit(string Name, string DistinguishedName);
internal sealed record ActiveDirectorySite(string Name, string DistinguishedName);
internal sealed record ActiveDirectoryStructureData(
    string DomainDistinguishedName,
    IReadOnlyList<ActiveDirectoryOrganizationalUnit> OrganizationalUnits,
    IReadOnlyList<ActiveDirectorySite> Sites,
    IReadOnlyList<string>? DiscoveryWarnings = null)
{
    public IReadOnlyList<string> Warnings => DiscoveryWarnings ?? [];
}

internal interface IActiveDirectoryStructureSource
{
    ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken);
}

internal sealed class FallbackActiveDirectoryStructureSource(
    IActiveDirectoryStructureSource primary,
    IActiveDirectoryStructureSource fallback) : IActiveDirectoryStructureSource
{
    public ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken)
    {
        try
        {
            return primary.GetStructure(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ActiveDirectoryStructureDiscoveryException primaryException)
        {
            try
            {
                var result = fallback.GetStructure(cancellationToken);
                return result with
                {
                    DiscoveryWarnings = result.Warnings
                        .Append("OU yapısı doğrudan sorgulanamadı; bilgisayar nesnelerinin DN bilgileri kullanıldı.")
                        .ToArray()
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception fallbackException) when (IsRecoverableDirectoryFailure(fallbackException))
            {
                throw new ActiveDirectoryStructureDiscoveryException(
                    "Active Directory structure discovery and computer-DN fallback failed.",
                    new AggregateException(primaryException, fallbackException));
            }
        }
    }

    private static bool IsRecoverableDirectoryFailure(Exception exception) =>
        exception is not OutOfMemoryException and not AccessViolationException;
}

internal sealed class DirectoryServicesStructureSource : IActiveDirectoryStructureSource
{
    private static readonly TimeSpan SearchTimeout = TimeSpan.FromSeconds(15);

    public ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var rootDse = CreateEntry("LDAP://RootDSE");
            var domainDn = GetRequiredProperty(rootDse, "defaultNamingContext");
            var organizationalUnits = FindEntries(
                $"LDAP://{domainDn}",
                "(objectCategory=organizationalUnit)",
                "name",
                cancellationToken,
                (name, distinguishedName) => new ActiveDirectoryOrganizationalUnit(name, distinguishedName));

            var warnings = new List<string>();
            IReadOnlyList<ActiveDirectorySite> sites = [];
            try
            {
                var configurationDn = GetRequiredProperty(rootDse, "configurationNamingContext");
                sites = FindEntries(
                    $"LDAP://CN=Sites,{configurationDn}",
                    "(objectClass=site)",
                    "name",
                    cancellationToken,
                    (name, distinguishedName) => new ActiveDirectorySite(name, distinguishedName));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (IsRecoverableDirectoryFailure(ex))
            {
                warnings.Add($"AD site listesi alınamadı ({GetFailureCategory(ex)}); OU listesi kullanılabilir.");
            }

            return new ActiveDirectoryStructureData(domainDn, organizationalUnits, sites, warnings);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (IsRecoverableDirectoryFailure(ex))
        {
            throw new ActiveDirectoryStructureDiscoveryException(
                "Active Directory structure discovery failed.",
                ex);
        }
    }

    private static IReadOnlyList<T> FindEntries<T>(
        string rootPath,
        string filter,
        string nameProperty,
        CancellationToken cancellationToken,
        Func<string, string, T> factory)
    {
        using var root = CreateEntry(rootPath);
        using var searcher = new DirectorySearcher(root)
        {
            Filter = filter,
            PageSize = 1000,
            SearchScope = SearchScope.Subtree,
            ClientTimeout = SearchTimeout,
            ServerTimeLimit = SearchTimeout,
            ReferralChasing = ReferralChasingOption.None
        };
        searcher.PropertiesToLoad.Add(nameProperty);
        searcher.PropertiesToLoad.Add("distinguishedName");

        using var results = searcher.FindAll();
        var entries = new List<T>();
        foreach (SearchResult result in results)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = GetFirstString(result, nameProperty);
            var distinguishedName = GetFirstString(result, "distinguishedName");
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(distinguishedName))
            {
                continue;
            }

            entries.Add(factory(name, distinguishedName));
        }

        return entries;
    }

    private static DirectoryEntry CreateEntry(string path) =>
        new(path, null, null, AuthenticationTypes.Secure);

    private static string GetRequiredProperty(DirectoryEntry entry, string propertyName)
    {
        var value = entry.Properties[propertyName]?.Value?.ToString();
        return string.IsNullOrWhiteSpace(value)
            ? throw new InvalidOperationException($"RootDSE property is missing: {propertyName}.")
            : value;
    }

    private static string? GetFirstString(SearchResult result, string propertyName) =>
        result.Properties[propertyName]?.Count > 0
            ? result.Properties[propertyName][0]?.ToString()
            : null;

    private static bool IsRecoverableDirectoryFailure(Exception exception) =>
        exception is not OutOfMemoryException and not AccessViolationException;

    private static string GetFailureCategory(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "access denied",
        DirectoryServicesCOMException or COMException => "LDAP/COM",
        TimeoutException => "timeout",
        _ => exception.GetType().Name
    };
}

internal sealed class ComputerDerivedStructureSource(IActiveDirectoryComputerSource computerSource)
    : IActiveDirectoryStructureSource
{
    private static readonly Regex HexEscape = new(@"\\([0-9A-Fa-f]{2})", RegexOptions.CultureInvariant);

    public ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken)
    {
        try
        {
            var computers = computerSource.GetComputers(cancellationToken);
            var distinguishedNames = computers
                .Select(x => x.DistinguishedName)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Cast<string>()
                .ToArray();
            var domainDn = distinguishedNames
                .Select(ExtractDomainDistinguishedName)
                .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))
                ?? throw new InvalidOperationException("Computer objects did not contain a domain distinguished name.");

            var organizationalUnits = distinguishedNames
                .SelectMany(ExtractOrganizationalUnits)
                .GroupBy(x => x.DistinguishedName, StringComparer.OrdinalIgnoreCase)
                .Select(x => x.First())
                .ToArray();
            var sites = computers
                .Select(x => x.Site?.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Cast<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(name => new ActiveDirectorySite(
                    name,
                    $"CN={name},CN=Sites,CN=Configuration,{domainDn}"))
                .ToArray();

            return new ActiveDirectoryStructureData(domainDn, organizationalUnits, sites);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not AccessViolationException)
        {
            throw new ActiveDirectoryStructureDiscoveryException(
                "Active Directory structure could not be derived from computer objects.",
                ex);
        }
    }

    internal static IReadOnlyList<ActiveDirectoryOrganizationalUnit> ExtractOrganizationalUnits(string distinguishedName)
    {
        var components = SplitDistinguishedName(distinguishedName);
        return components
            .Select((component, index) => new { Component = component, Index = index })
            .Where(x => x.Component.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
            .Select(x => new ActiveDirectoryOrganizationalUnit(
                UnescapeRdnValue(x.Component[3..]),
                string.Join(',', components.Skip(x.Index))))
            .ToArray();
    }

    internal static string? ExtractDomainDistinguishedName(string distinguishedName)
    {
        var components = SplitDistinguishedName(distinguishedName);
        var firstDomainComponent = components.FindIndex(x => x.StartsWith("DC=", StringComparison.OrdinalIgnoreCase));
        return firstDomainComponent < 0
            ? null
            : string.Join(',', components.Skip(firstDomainComponent));
    }

    private static List<string> SplitDistinguishedName(string distinguishedName)
    {
        var components = new List<string>();
        var start = 0;
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

            if (escapeCount % 2 != 0)
            {
                continue;
            }

            components.Add(distinguishedName[start..index].Trim());
            start = index + 1;
        }
        components.Add(distinguishedName[start..].Trim());
        return components;
    }

    private static string UnescapeRdnValue(string value)
    {
        var decoded = HexEscape.Replace(value, match =>
            ((char)Convert.ToByte(match.Groups[1].Value, 16)).ToString());
        return decoded
            .Replace("\\,", ",", StringComparison.Ordinal)
            .Replace("\\+", "+", StringComparison.Ordinal)
            .Replace("\\\"", "\"", StringComparison.Ordinal)
            .Replace("\\\\", "\\", StringComparison.Ordinal)
            .Trim();
    }
}

internal sealed class ActiveDirectoryStructureDiscoveryException(string message, Exception innerException)
    : Exception(message, innerException);
