using System.DirectoryServices;
using System.Runtime.InteropServices;

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
    IReadOnlyList<ActiveDirectorySiteScope> Sites);

public interface IActiveDirectoryStructureProvider
{
    Task<ActiveDirectoryStructure> GetStructureAsync(CancellationToken cancellationToken);
}

public sealed class ActiveDirectoryStructureProvider : IActiveDirectoryStructureProvider
{
    private readonly IActiveDirectoryStructureSource _source;

    public ActiveDirectoryStructureProvider()
        : this(new DirectoryServicesStructureSource())
    {
    }

    internal ActiveDirectoryStructureProvider(IActiveDirectoryStructureSource source)
    {
        _source = source;
    }

    public Task<ActiveDirectoryStructure> GetStructureAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var raw = _source.GetStructure(cancellationToken);
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

        return Task.FromResult(new ActiveDirectoryStructure(
            raw.DomainDistinguishedName.Trim(),
            organizationalUnits,
            sites));
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
    IReadOnlyList<ActiveDirectorySite> Sites);

internal interface IActiveDirectoryStructureSource
{
    ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken);
}

internal sealed class DirectoryServicesStructureSource : IActiveDirectoryStructureSource
{
    public ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var rootDse = new DirectoryEntry("LDAP://RootDSE");
            var domainDn = GetRequiredProperty(rootDse, "defaultNamingContext");
            var configurationDn = GetRequiredProperty(rootDse, "configurationNamingContext");
            var organizationalUnits = FindEntries(
                $"LDAP://{domainDn}",
                "(objectCategory=organizationalUnit)",
                "name",
                cancellationToken,
                (name, distinguishedName) => new ActiveDirectoryOrganizationalUnit(name, distinguishedName));
            var sites = FindEntries(
                $"LDAP://CN=Sites,{configurationDn}",
                "(objectClass=site)",
                "name",
                cancellationToken,
                (name, distinguishedName) => new ActiveDirectorySite(name, distinguishedName));

            return new ActiveDirectoryStructureData(domainDn, organizationalUnits, sites);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is DirectoryServicesCOMException or
                                   COMException or
                                   InvalidOperationException or
                                   UnauthorizedAccessException)
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
        using var root = new DirectoryEntry(rootPath);
        using var searcher = new DirectorySearcher(root)
        {
            Filter = filter,
            PageSize = 1000,
            SearchScope = SearchScope.Subtree
        };
        searcher.PropertiesToLoad.Add(nameProperty);
        searcher.PropertiesToLoad.Add("distinguishedName");

        using var results = searcher.FindAll();
        var entries = new List<T>(results.Count);
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
}

internal sealed class ActiveDirectoryStructureDiscoveryException(string message, Exception innerException)
    : Exception(message, innerException);
