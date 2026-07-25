using System.DirectoryServices;

namespace O365AuditTool.Services;

public record DeviceTarget(string Name, string? Ou = null, string? Site = null);

public interface IDeviceTargetProvider
{
    Task<IReadOnlyList<DeviceTarget>> GetTargetsAsync(string? ouFilter, string? siteFilter, CancellationToken cancellationToken);
}

public class ActiveDirectoryTargetProvider(IConfiguration configuration, ILogger<ActiveDirectoryTargetProvider> logger) : IDeviceTargetProvider
{
    public Task<IReadOnlyList<DeviceTarget>> GetTargetsAsync(string? ouFilter, string? siteFilter, CancellationToken cancellationToken)
    {
        try
        {
            var root = new DirectoryEntry();
            using var searcher = new DirectorySearcher(root)
            {
                Filter = "(&(objectCategory=computer)(objectClass=computer))",
                PageSize = 1000
            };

            searcher.PropertiesToLoad.Add("name");
            searcher.PropertiesToLoad.Add("distinguishedName");

            var results = searcher.FindAll();
            var devices = new List<DeviceTarget>(results.Count);
            foreach (SearchResult result in results)
            {
                var name = result.Properties["name"]?.Count > 0 ? result.Properties["name"][0]?.ToString() : null;
                var dn = result.Properties["distinguishedName"]?.Count > 0 ? result.Properties["distinguishedName"][0]?.ToString() : null;
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(ouFilter) && (dn is null || !dn.Contains(ouFilter, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                devices.Add(new DeviceTarget(name, dn, siteFilter));
            }

            if (devices.Count > 0)
            {
                return Task.FromResult<IReadOnlyList<DeviceTarget>>(devices);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "AD target discovery failed, falling back to configured targets.");
        }

        var fallbackTargets = configuration.GetSection("Collector:FallbackTargets").Get<string[]>() ?? [];
        var fallback = fallbackTargets.Select(x => new DeviceTarget(x.Trim())).Where(x => !string.IsNullOrWhiteSpace(x.Name)).ToArray();
        return Task.FromResult<IReadOnlyList<DeviceTarget>>(fallback);
    }
}
