using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class ArtifactCopyPathTests
{
    [Theory]
    [InlineData("PC-001", @"C:\Users\ali\mail.pst", @"\\PC-001\C$\Users\ali\mail.pst")]
    [InlineData("pc01.corp.example", @"d:/archive/mail.nk2", @"\\pc01.corp.example\D$\archive\mail.nk2")]
    public void ToAdministrativeShare_ConvertsLocalPathForValidHost(
        string device,
        string source,
        string expected)
    {
        Assert.Equal(expected, ArtifactCopyPath.ToAdministrativeShare(device, source));
    }

    [Fact]
    public void ToAdministrativeShare_LeavesValidUncPathUnchanged()
    {
        const string source = @"\\fileserver\profiles\ali\mail.pst";

        Assert.Equal(source, ArtifactCopyPath.ToAdministrativeShare("PC-001", source));
    }

    [Theory]
    [InlineData(@"PC-001\OtherShare")]
    [InlineData("PC-001/OtherShare")]
    [InlineData("PC-001..corp")]
    [InlineData("-PC-001")]
    [InlineData("PC-001-")]
    public void ToAdministrativeShare_RejectsShareInjectionAndInvalidHostnames(string device)
    {
        Assert.Throws<ArtifactCopyValidationException>(
            () => ArtifactCopyPath.ToAdministrativeShare(device, @"C:\Users\ali\mail.pst"));
    }

    [Theory]
    [InlineData(@"C:\Users\ali\..\admin\mail.pst")]
    [InlineData(@"C:\Users\.\ali\mail.pst")]
    [InlineData(@"C:\Users\ali\mail.pst:secret")]
    [InlineData(@"\\server\share\..\other\mail.pst")]
    [InlineData(@"\\?\C:\Users\ali\mail.pst")]
    public void ToAdministrativeShare_RejectsTraversalAndDevicePaths(string source)
    {
        Assert.Throws<ArtifactCopyValidationException>(
            () => ArtifactCopyPath.ToAdministrativeShare("PC-001", source));
    }

    [Theory]
    [InlineData(@"DOMAIN\ali:finance", "DOMAIN_ali_finance")]
    [InlineData(@"..\CON", ".._CON")]
    [InlineData("AUX", "_AUX")]
    [InlineData("name. ", "name")]
    [InlineData("***", "_")]
    public void SanitizeComponent_RemovesWindowsUnsafeCharacters(string input, string expected)
    {
        Assert.Equal(expected, ArtifactCopyPath.SanitizeComponent(input));
    }

    [Fact]
    public void BuildDestinationPath_UsesSanitizedHierarchyAndStableHashSuffix()
    {
        var first = ArtifactCopyPath.BuildDestinationPath(
            @"C:\Migration",
            @"DOMAIN\ali",
            "PC-001",
            "Outlook:Default",
            "pst",
            @"C:\Users\ali\Documents\archive.pst");
        var second = ArtifactCopyPath.BuildDestinationPath(
            @"C:\Migration",
            @"DOMAIN\ali",
            "PC-001",
            "Outlook:Default",
            "pst",
            @"C:\Users\ali\Documents\archive.pst");

        Assert.Equal(first, second);
        Assert.Contains(
            Path.Combine("DOMAIN_ali", "PC-001", "Outlook_Default", "PST"),
            first,
            StringComparison.OrdinalIgnoreCase);
        Assert.Matches(@"archive_[0-9A-F]{12}\.pst$", first);
    }

    [Fact]
    public void BuildDestinationPath_DifferentSourcesGetDifferentCollisionSuffixes()
    {
        var first = ArtifactCopyPath.BuildDestinationPath(
            @"C:\Migration",
            "ali@example.com",
            "PC-001",
            "Default",
            "PST",
            @"C:\Mail\archive.pst");
        var second = ArtifactCopyPath.BuildDestinationPath(
            @"C:\Migration",
            "ali@example.com",
            "PC-001",
            "Default",
            "PST",
            @"D:\Mail\archive.pst");

        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData(@"C:\Migration", @"C:\Migration", true)]
    [InlineData(@"C:\Migration\User", @"C:\Migration", true)]
    [InlineData(@"c:\migration\User", @"C:\Migration", true)]
    [InlineData(@"C:\MigrationEvil", @"C:\Migration", false)]
    [InlineData(@"C:\Other", @"C:\Migration", false)]
    [InlineData(@"C:\Migration", @"C:\", true)]
    public void TryValidateAllowedRoot_IsSeparatorAware(
        string target,
        string allowed,
        bool expected)
    {
        var result = ArtifactCopyPath.TryValidateAllowedRoot(
            target,
            [allowed],
            out var normalized,
            out var error);

        Assert.Equal(expected, result);
        Assert.Equal(expected, string.IsNullOrEmpty(error));
        Assert.Equal(Path.TrimEndingDirectorySeparator(Path.GetFullPath(target)), normalized);
    }

    [Fact]
    public void TryValidateAllowedRoot_FailsClosedWhenNoRootsConfigured()
    {
        var result = ArtifactCopyPath.TryValidateAllowedRoot(
            @"C:\Migration",
            [],
            out _,
            out var error);

        Assert.False(result);
        Assert.Contains("AllowedTargetRoots", error, StringComparison.Ordinal);
    }
}
