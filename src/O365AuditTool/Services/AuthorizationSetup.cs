using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace O365AuditTool.Services;

public static class AuthorizationSetup
{
    public static IServiceCollection AddAuditAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationHandler, RoleMappingAuthorizationHandler>();

        services.AddAuthorization(options =>
        {
            options.AddPolicy("AuditAdmin", p => p.Requirements.Add(new RoleMappingRequirement("AuditAdmin")));
            options.AddPolicy("AuditReader", p => p.Requirements.Add(new RoleMappingRequirement("AuditReader")));
            options.AddPolicy("MigrationPlanner", p => p.Requirements.Add(new RoleMappingRequirement("MigrationPlanner")));
        });

        return services;
    }
}

public class RoleMappingRequirement(string appRole) : IAuthorizationRequirement
{
    public string AppRole { get; } = appRole;
}

public class RoleMappingAuthorizationHandler(IOptions<AuthOptions> authOptions) : AuthorizationHandler<RoleMappingRequirement>
{
    private static readonly IReadOnlyDictionary<string, string[]> SatisfyingRoles =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["AuditAdmin"] = ["AuditAdmin"],
            ["AuditReader"] = ["AuditReader", "AuditAdmin"],
            ["MigrationPlanner"] = ["MigrationPlanner", "AuditAdmin"]
        };

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleMappingRequirement requirement)
    {
        var user = context.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            return Task.CompletedTask;
        }

        if (!SatisfyingRoles.TryGetValue(requirement.AppRole, out var satisfyingRoles))
        {
            return Task.CompletedTask;
        }

        var roleMappings = authOptions.Value.RoleMappings;
        if (roleMappings is null)
        {
            return Task.CompletedTask;
        }

        foreach (var satisfyingRole in satisfyingRoles)
        {
            if (!roleMappings.TryGetValue(satisfyingRole, out var mappedRoles) || mappedRoles is null)
            {
                continue;
            }

            foreach (var mappedRole in mappedRoles.Where(role => !string.IsNullOrWhiteSpace(role)))
            {
                if (user.IsInRole(mappedRole) ||
                    user.Claims.Any(c =>
                        c.Type == ClaimTypes.Role &&
                        string.Equals(c.Value, mappedRole, StringComparison.OrdinalIgnoreCase)))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }
            }
        }

        return Task.CompletedTask;
    }
}
