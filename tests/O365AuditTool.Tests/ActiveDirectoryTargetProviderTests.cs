using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class ActiveDirectoryTargetProviderTests
{
    [Fact]
    public async Task GetTargetsAsync_AppliesRealSiteFilterWithoutRelabelingDevices()
    {
        var provider = CreateProvider(
        [
            new ActiveDirectoryComputer("PC-A", "CN=PC-A,OU=Finance,DC=contoso,DC=local", "ISTANBUL"),
            new ActiveDirectoryComputer("PC-B", "CN=PC-B,OU=Finance,DC=contoso,DC=local", "ANKARA"),
            new ActiveDirectoryComputer("PC-C", "CN=PC-C,OU=Finance,DC=contoso,DC=local", null)
        ]);

        var targets = await provider.GetTargetsAsync(null, "istanbul", CancellationToken.None);

        var target = Assert.Single(targets);
        Assert.Equal("PC-A", target.Name);
        Assert.Equal("OU=Finance,DC=contoso,DC=local", target.Ou);
        Assert.Equal("ISTANBUL", target.Site);
    }

    [Fact]
    public void GetParentDistinguishedName_HandlesEscapedCommaInComputerName()
    {
        var parent = ActiveDirectoryTargetProvider.GetParentDistinguishedName(
            @"CN=PC\, Special,OU=Finance,DC=contoso,DC=local");

        Assert.Equal("OU=Finance,DC=contoso,DC=local", parent);
    }

    [Fact]
    public async Task GetTargetsAsync_ReturnsNoTargetsWhenRequestedSiteCannotBeVerified()
    {
        var provider = CreateProvider(
            [new ActiveDirectoryComputer("PC-A", "CN=PC-A,OU=Finance,DC=contoso,DC=local", null)],
            ["FALLBACK-01"]);

        var targets = await provider.GetTargetsAsync(null, "ISTANBUL", CancellationToken.None);

        Assert.Empty(targets);
    }

    [Fact]
    public async Task GetTargetsAsync_ExcludesDisabledComputers()
    {
        var provider = CreateProvider(
        [
            new ActiveDirectoryComputer("PC-ENABLED", "CN=PC-ENABLED,OU=Finance,DC=contoso,DC=local", "ISTANBUL"),
            new ActiveDirectoryComputer("PC-DISABLED", "CN=PC-DISABLED,OU=Finance,DC=contoso,DC=local", "ISTANBUL", false)
        ]);

        var targets = await provider.GetTargetsAsync("OU=Finance", null, CancellationToken.None);

        Assert.Equal("PC-ENABLED", Assert.Single(targets).Name);
        Assert.Contains("1.2.840.113556.1.4.803:=2", DirectoryServicesComputerSource.ComputerFilter);
    }

    [Fact]
    public async Task GetTargetsAsync_DoesNotUseFallbackWhenOuHasNoMatches()
    {
        var provider = CreateProvider(
            [new ActiveDirectoryComputer("PC-A", "CN=PC-A,OU=Finance,DC=contoso,DC=local", "ISTANBUL")],
            ["FALLBACK-01"]);

        var targets = await provider.GetTargetsAsync("OU=Legal", null, CancellationToken.None);

        Assert.Empty(targets);
    }

    [Fact]
    public async Task GetTargetsAsync_UsesOnlyExplicitFallbackAfterAdFailure()
    {
        var provider = CreateProvider(
            _ => throw new ActiveDirectoryDiscoveryException("AD unavailable", new InvalidOperationException()),
            [" pc-b ", "PC-A", "pc-a"]);

        var targets = await provider.GetTargetsAsync("OU=Finance", "ISTANBUL", CancellationToken.None);

        Assert.Equal(2, targets.Count);
        Assert.Equal(["PC-A", "pc-b"], targets.Select(x => x.Name));
        Assert.All(targets, target =>
        {
            Assert.Null(target.Ou);
            Assert.Null(target.Site);
        });
    }

    [Fact]
    public async Task GetTargetsAsync_ThrowsExplicitErrorWhenAdFailsWithoutFallback()
    {
        var provider = CreateProvider(
            _ => throw new ActiveDirectoryDiscoveryException("AD unavailable", new InvalidOperationException()));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.GetTargetsAsync(null, null, CancellationToken.None));

        Assert.Contains("no explicit fallback", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTargetsAsync_DeduplicatesAndSortsNamesCaseInsensitively()
    {
        var provider = CreateProvider(
        [
            new ActiveDirectoryComputer("pc-b", "CN=pc-b,OU=Finance,DC=contoso,DC=local", "ISTANBUL"),
            new ActiveDirectoryComputer("pc-a", "CN=pc-a,OU=Finance,DC=contoso,DC=local", "ISTANBUL"),
            new ActiveDirectoryComputer("PC-A", "CN=PC-A,OU=Finance,DC=contoso,DC=local", "ISTANBUL")
        ]);

        var targets = await provider.GetTargetsAsync(null, null, CancellationToken.None);

        Assert.Equal(["PC-A", "pc-b"], targets.Select(x => x.Name));
    }

    [Fact]
    public async Task GetTargetsAsync_PropagatesCancellationWithoutUsingFallback()
    {
        var sourceCalled = false;
        var provider = CreateProvider(
            _ =>
            {
                sourceCalled = true;
                return [];
            },
            ["FALLBACK-01"]);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetTargetsAsync(null, null, cancellation.Token));

        Assert.False(sourceCalled);
    }

    private static ActiveDirectoryTargetProvider CreateProvider(
        IReadOnlyList<ActiveDirectoryComputer> computers,
        string[]? fallbackTargets = null) =>
        CreateProvider(_ => computers, fallbackTargets);

    private static ActiveDirectoryTargetProvider CreateProvider(
        Func<CancellationToken, IReadOnlyList<ActiveDirectoryComputer>> getComputers,
        string[]? fallbackTargets = null)
    {
        var values = new Dictionary<string, string?>();
        if (fallbackTargets is not null)
        {
            for (var index = 0; index < fallbackTargets.Length; index++)
            {
                values[$"Collector:FallbackTargets:{index}"] = fallbackTargets[index];
            }
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
        return new ActiveDirectoryTargetProvider(
            configuration,
            NullLogger<ActiveDirectoryTargetProvider>.Instance,
            new StubComputerSource(getComputers));
    }

    private sealed class StubComputerSource(
        Func<CancellationToken, IReadOnlyList<ActiveDirectoryComputer>> getComputers)
        : IActiveDirectoryComputerSource
    {
        public IReadOnlyList<ActiveDirectoryComputer> GetComputers(CancellationToken cancellationToken) =>
            getComputers(cancellationToken);
    }
}
