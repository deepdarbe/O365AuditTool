using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class AuthorizationSetupTests
{
    private static readonly AuthOptions Options = new()
    {
        RoleMappings = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["AuditAdmin"] = ["CONTOSO\\AuditAdmins"],
            ["AuditReader"] = ["CONTOSO\\AuditReaders"],
            ["MigrationPlanner"] = ["CONTOSO\\MigrationPlanners"]
        }
    };

    [Fact]
    public async Task MigrationPlanner_SatisfiesAuditReaderPolicy()
    {
        var context = await AuthorizeAsync("CONTOSO\\MigrationPlanners", "AuditReader");

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task AuditReader_DoesNotSatisfyMigrationPlannerPolicy()
    {
        var context = await AuthorizeAsync("CONTOSO\\AuditReaders", "MigrationPlanner");

        Assert.False(context.HasSucceeded);
    }

    private static async Task<AuthorizationHandlerContext> AuthorizeAsync(string role, string appRole)
    {
        var requirement = new RoleMappingRequirement(appRole);
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "CONTOSO\\user"), new Claim(ClaimTypes.Role, role)],
            "test",
            ClaimTypes.Name,
            ClaimTypes.Role);
        var context = new AuthorizationHandlerContext(
            [requirement],
            new ClaimsPrincipal(identity),
            resource: null);
        var handler = new RoleMappingAuthorizationHandler(Microsoft.Extensions.Options.Options.Create(Options));

        await handler.HandleAsync(context);
        return context;
    }
}
