using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public sealed class ActiveDirectoryStructureProviderTests
{
    [Fact]
    public async Task GetStructureAsync_BuildsSortedOuHierarchyAndDeduplicatesSites()
    {
        var provider = new ActiveDirectoryStructureProvider(new StubStructureSource(
            new ActiveDirectoryStructureData(
                "DC=contoso,DC=local",
                [
                    new("Workstations", "OU=Workstations,DC=contoso,DC=local"),
                    new("Finance", "OU=Finance,OU=Workstations,DC=contoso,DC=local"),
                    new("Servers", "OU=Servers,DC=contoso,DC=local")
                ],
                [
                    new("Istanbul-HQ", "CN=Istanbul-HQ,CN=Sites,CN=Configuration,DC=contoso,DC=local"),
                    new("istanbul-hq", "CN=duplicate,CN=Sites,CN=Configuration,DC=contoso,DC=local"),
                    new("Ankara", "CN=Ankara,CN=Sites,CN=Configuration,DC=contoso,DC=local")
                ])));

        var structure = await provider.GetStructureAsync(CancellationToken.None);

        Assert.Equal("DC=contoso,DC=local", structure.DomainDistinguishedName);
        Assert.Equal(3, structure.OrganizationalUnits.Count);
        var finance = Assert.Single(structure.OrganizationalUnits, x => x.Name == "Finance");
        Assert.Equal("Workstations / Finance", finance.DisplayName);
        Assert.Equal(2, finance.Depth);
        Assert.Equal("OU=Workstations,DC=contoso,DC=local", finance.ParentDistinguishedName);
        Assert.Equal(["Ankara", "Istanbul-HQ"], structure.Sites.Select(x => x.Name));
        Assert.Empty(structure.Warnings);
    }

    [Fact]
    public async Task GetStructureAsync_UsesComputerDnFallbackAndReturnsWarning()
    {
        var primary = new DelegateStructureSource(_ => throw new ActiveDirectoryStructureDiscoveryException(
            "LDAP OU query failed.",
            new InvalidOperationException("test")));
        var fallback = new StubStructureSource(new ActiveDirectoryStructureData(
            "DC=contoso,DC=local",
            [new("Finance", "OU=Finance,DC=contoso,DC=local")],
            []));
        var provider = new ActiveDirectoryStructureProvider(
            new FallbackActiveDirectoryStructureSource(primary, fallback));

        var structure = await provider.GetStructureAsync(CancellationToken.None);

        Assert.Single(structure.OrganizationalUnits);
        Assert.Contains(structure.Warnings, x => x.Contains("bilgisayar nesnelerinin DN", StringComparison.Ordinal));
    }

    [Fact]
    public void ComputerDnFallback_ExtractsNestedAndEscapedOrganizationalUnits()
    {
        const string distinguishedName = @"CN=PC-01,OU=Finance\, Europe,OU=Workstations,DC=contoso,DC=local";

        var organizationalUnits = ComputerDerivedStructureSource.ExtractOrganizationalUnits(distinguishedName);

        Assert.Equal("DC=contoso,DC=local", ComputerDerivedStructureSource.ExtractDomainDistinguishedName(distinguishedName));
        Assert.Equal(2, organizationalUnits.Count);
        Assert.Equal("Finance, Europe", organizationalUnits[0].Name);
        Assert.Equal(@"OU=Finance\, Europe,OU=Workstations,DC=contoso,DC=local", organizationalUnits[0].DistinguishedName);
        Assert.Equal("Workstations", organizationalUnits[1].Name);
    }

    [Fact]
    public async Task GetStructureAsync_PropagatesCancellationBeforeLdapSourceIsCalled()
    {
        var called = false;
        var provider = new ActiveDirectoryStructureProvider(new DelegateStructureSource(_ =>
        {
            called = true;
            return new ActiveDirectoryStructureData("DC=contoso,DC=local", [], []);
        }));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetStructureAsync(cancellation.Token));
        Assert.False(called);
    }

    private sealed class StubStructureSource(ActiveDirectoryStructureData data) : IActiveDirectoryStructureSource
    {
        public ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken) => data;
    }

    private sealed class DelegateStructureSource(
        Func<CancellationToken, ActiveDirectoryStructureData> callback) : IActiveDirectoryStructureSource
    {
        public ActiveDirectoryStructureData GetStructure(CancellationToken cancellationToken) => callback(cancellationToken);
    }
}
