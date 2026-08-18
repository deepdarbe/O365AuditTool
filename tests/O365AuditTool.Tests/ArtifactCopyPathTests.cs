using System.Diagnostics;
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
    public void ToAdministrativeShare_RejectsUncPathByDefault()
    {
        const string source = @"\\fileserver\profiles\ali\mail.pst";

        var exception = Assert.Throws<ArtifactCopyValidationException>(
            () => ArtifactCopyPath.ToAdministrativeShare("PC-001", source));

        Assert.Contains("AllowedSourceUncRoots", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ToAdministrativeShare_AllowsOnlyConfiguredUncRoot()
    {
        const string source = @"\\fileserver\profiles\ali\mail.pst";

        var result = ArtifactCopyPath.ToAdministrativeShare(
            "PC-001",
            source,
            "PST",
            [@"\\fileserver\profiles"]);

        Assert.Equal(source, result);
        Assert.Throws<ArtifactCopyValidationException>(() =>
            ArtifactCopyPath.ToAdministrativeShare(
                "PC-001",
                @"\\fileserver\profiles-evil\ali\mail.pst",
                "PST",
                [@"\\fileserver\profiles"]));
    }

    [Theory]
    [InlineData(@"C:\Users\ali\mail.exe", "PST")]
    [InlineData(@"C:\Users\ali\mail.nk2", "PST")]
    [InlineData(@"C:\Users\ali\mail.pst", "UNKNOWN")]
    public void ToAdministrativeShare_RejectsUnsupportedOrMismatchedArtifactType(
        string source,
        string artifactType)
    {
        Assert.Throws<ArtifactCopyValidationException>(() =>
            ArtifactCopyPath.ToAdministrativeShare("PC-001", source, artifactType));
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

    [Fact]
    public void TryValidateAllowedRoot_RejectsExistingReparsePointInDestinationChain()
    {
        var testRoot = Path.Combine(Path.GetTempPath(), $"o365-copy-root-{Guid.NewGuid():N}");
        var outsideRoot = Path.Combine(Path.GetTempPath(), $"o365-copy-outside-{Guid.NewGuid():N}");
        var linkPath = Path.Combine(testRoot, "linked");
        Directory.CreateDirectory(testRoot);
        Directory.CreateDirectory(outsideRoot);

        try
        {
            CreateDirectoryLink(linkPath, outsideRoot);

            var result = ArtifactCopyPath.TryValidateAllowedRoot(
                Path.Combine(linkPath, "mail.pst"),
                [testRoot],
                out _,
                out var error);

            Assert.False(result);
            Assert.Contains("reparse point", error, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(linkPath))
            {
                Directory.Delete(linkPath);
            }

            Directory.Delete(testRoot, recursive: true);
            Directory.Delete(outsideRoot, recursive: true);
        }
    }

    private static void CreateDirectoryLink(string linkPath, string targetPath)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
            return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Directory junctions do not require the Windows symbolic-link privilege.
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("mklink");
        startInfo.ArgumentList.Add("/J");
        startInfo.ArgumentList.Add(linkPath);
        startInfo.ArgumentList.Add(targetPath);

        using var process = Process.Start(startInfo);
        Assert.NotNull(process);
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(
            process.ExitCode == 0,
            $"Unable to create test junction. Output: {output} Error: {error}");
    }
}
