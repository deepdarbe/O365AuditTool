using O365AuditTool.Models;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

public class ScanOrchestratorSchedulingTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BuildDailyScheduledJob_FailsClosedWhenDefaultScopeIsEmpty(string? defaultOuFilter)
    {
        var utcNow = new DateTime(2026, 8, 10, 8, 30, 0, DateTimeKind.Utc);

        var job = ScanOrchestratorService.BuildDailyScheduledJob(
            new CollectorOptions { DefaultOuFilter = defaultOuFilter },
            utcNow);

        Assert.Equal("scheduler", job.RequestedBy);
        Assert.Equal(JobStatus.Failed, job.Status);
        Assert.Null(job.OuFilter);
        Assert.Null(job.SiteFilter);
        Assert.Equal(utcNow, job.CreatedUtc);
        Assert.Equal(utcNow, job.CompletedUtc);
        Assert.Contains("explicit AD scope", job.Notes, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildDailyScheduledJob_QueuesOnlyExplicitNormalizedOuScope()
    {
        var utcNow = new DateTime(2026, 8, 10, 8, 30, 0, DateTimeKind.Utc);

        var job = ScanOrchestratorService.BuildDailyScheduledJob(
            new CollectorOptions { DefaultOuFilter = "  OU=Workstations,DC=contoso,DC=local  " },
            utcNow);

        Assert.Equal(JobStatus.Queued, job.Status);
        Assert.Equal("OU=Workstations,DC=contoso,DC=local", job.OuFilter);
        Assert.Null(job.SiteFilter);
        Assert.Null(job.CompletedUtc);
        Assert.Null(job.Notes);
    }

    [Fact]
    public void BuildDailyScheduledJob_QueuesExplicitSiteScope()
    {
        var utcNow = new DateTime(2026, 8, 10, 8, 30, 0, DateTimeKind.Utc);

        var job = ScanOrchestratorService.BuildDailyScheduledJob(
            new CollectorOptions { DefaultSiteFilter = "  Istanbul-HQ  " },
            utcNow);

        Assert.Equal(JobStatus.Queued, job.Status);
        Assert.Null(job.OuFilter);
        Assert.Equal("Istanbul-HQ", job.SiteFilter);
    }
}
