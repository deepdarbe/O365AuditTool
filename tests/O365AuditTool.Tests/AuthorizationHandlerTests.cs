using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class AuthorizationHandlerTests
{
    [Fact]
    public async Task AuditReader_FailsClosedForAuthenticatedUserWithoutMappedGroup()
    {
        var result = await AuthorizeAsync("AuditReader", []);

        Assert.False(result.HasSucceeded);
    }

    [Theory]
    [InlineData("AuditReader", "DOMAIN\\GG_O365_Audit_Read")]
    [InlineData("AuditReader", "DOMAIN\\GG_O365_Audit_Admin")]
    [InlineData("MigrationPlanner", "DOMAIN\\GG_O365_Audit_Admin")]
    [InlineData("AuditAdmin", "DOMAIN\\GG_O365_Audit_Admin")]
    public async Task RoleHierarchy_AllowsExpectedMappedGroups(string policy, string group)
    {
        var result = await AuthorizeAsync(policy, [group]);

        Assert.True(result.HasSucceeded);
    }

    [Fact]
    public async Task AuditAdmin_DoesNotAcceptReaderGroup()
    {
        var result = await AuthorizeAsync("AuditAdmin", ["DOMAIN\\GG_O365_Audit_Read"]);

        Assert.False(result.HasSucceeded);
    }

    private static async Task<AuthorizationHandlerContext> AuthorizeAsync(
        string policy,
        IReadOnlyCollection<string> groupClaims)
    {
        var options = Options.Create(new AuthOptions
        {
            RoleMappings = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["AuditAdmin"] = ["DOMAIN\\GG_O365_Audit_Admin"],
                ["AuditReader"] = ["DOMAIN\\GG_O365_Audit_Read"],
                ["MigrationPlanner"] = ["DOMAIN\\GG_O365_Migration_Planner"]
            }
        });

        var claims = new List<Claim> { new(ClaimTypes.Name, "DOMAIN\\test.user") };
        claims.AddRange(groupClaims.Select(group => new Claim(ClaimTypes.Role, group)));
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "Negotiate"));
        var requirement = new RoleMappingRequirement(policy);
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = new RoleMappingAuthorizationHandler(options);

        await handler.HandleAsync(context);
        return context;
    }
}
