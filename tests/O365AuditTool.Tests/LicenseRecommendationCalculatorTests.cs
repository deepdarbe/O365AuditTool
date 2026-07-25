using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class LicenseRecommendationCalculatorTests
{
    private const long GiB = 1024L * 1024 * 1024;

    [Fact]
    public void Calculate_DeduplicatesSameLocalPathOnSameDevice()
    {
        var inputs = new[]
        {
            Pst("user@example.com", "PC-01", @"C:\Users\User\archive.pst", 30 * GiB),
            Pst("user@example.com", "PC-01", @"c:/users/user/archive.pst", 30 * GiB)
        };

        var result = Assert.Single(LicenseRecommendationCalculator.Calculate(inputs));

        Assert.Equal(30 * GiB, result.TotalPstBytes);
        Assert.Equal("Exchange Online Plan 1", result.RecommendedLicense);
    }

    [Fact]
    public void Calculate_KeepsSameLocalPathOnDifferentDevices()
    {
        var inputs = new[]
        {
            Pst("user@example.com", "PC-01", @"C:\Users\User\archive.pst", 30 * GiB),
            Pst("user@example.com", "PC-02", @"C:\Users\User\archive.pst", 30 * GiB)
        };

        var result = Assert.Single(LicenseRecommendationCalculator.Calculate(inputs));

        Assert.Equal(60 * GiB, result.TotalPstBytes);
        Assert.Equal("Exchange Online Plan 2", result.RecommendedLicense);
    }

    [Fact]
    public void Calculate_DeduplicatesSameUncPathAcrossDevices()
    {
        var inputs = new[]
        {
            Pst("user@example.com", "PC-01", @"\\fileserver\pst\archive.pst", 60 * GiB),
            Pst("user@example.com", "PC-02", @"\\FILESERVER\PST\archive.pst", 60 * GiB)
        };

        var result = Assert.Single(LicenseRecommendationCalculator.Calculate(inputs));

        Assert.Equal(60 * GiB, result.TotalPstBytes);
    }

    [Theory]
    [InlineData(50, "Exchange Online Plan 1")]
    [InlineData(51, "Exchange Online Plan 2")]
    [InlineData(100, "Exchange Online Plan 2")]
    [InlineData(101, "Exchange Online Plan 2 + Online Archive")]
    public void Calculate_AppliesLicenseThresholds(long sizeGb, string expected)
    {
        var result = Assert.Single(LicenseRecommendationCalculator.Calculate(
            [Pst("user@example.com", "PC-01", @"C:\archive.pst", sizeGb * GiB)]));

        Assert.Equal(expected, result.RecommendedLicense);
    }

    [Fact]
    public void Calculate_LowersConfidenceWhenFileIsMissing()
    {
        var result = Assert.Single(LicenseRecommendationCalculator.Calculate(
            [Pst("user@example.com", "PC-01", @"C:\missing.pst", 0, exists: false)]));

        Assert.Equal("Low", result.Confidence);
    }

    private static PstLicenseInput Pst(
        string user,
        string device,
        string path,
        long size,
        bool exists = true) =>
        new(user, device, path, size, exists);
}
