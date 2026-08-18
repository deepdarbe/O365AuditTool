using O365AuditTool.Services;
using Xunit;
using Models = O365AuditTool.Models;

namespace O365AuditTool.Tests;

public class PsExecCollectorRunnerTests
{
    [Theory]
    [InlineData(53, "localized operating system error")]
    [InlineData(1, "The RPC server is unavailable.")]
    [InlineData(1, "No such host is known.")]
    [InlineData(1, "Ağ yolu bulunamadı.")]
    public void IsOfflineFailure_RecognizesTransientNetworkFailures(int exitCode, string error)
    {
        Assert.True(PsExecCollectorRunner.IsOfflineFailure(exitCode, error));
    }

    [Fact]
    public void IsOfflineFailure_DoesNotRetryAuthorizationFailures()
    {
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(5, "Access is denied."));
    }

    [Fact]
    public void GetFailureStatus_DistinguishesTimeoutFromOffline()
    {
        var timedOut = new CollectResult(false, null, "timeout", IsOffline: false, IsTimedOut: true);
        var offline = new CollectResult(false, null, "offline", IsOffline: true);

        Assert.Equal(Models.DeviceScanStatus.Timeout, ScanOrchestratorService.GetFailureStatus(timedOut));
        Assert.Equal(Models.DeviceScanStatus.Offline, ScanOrchestratorService.GetFailureStatus(offline));
    }

    [Fact]
    public void TryNormalizePayload_AcceptsFqdnTargetAndInitializesNullCollections()
    {
        var payload = new Models.CollectorPayload
        {
            SchemaVersion = "1.2",
            Device = new Models.CollectorDevice { Hostname = "PC-01", Ips = null! },
            Profiles = null!
        };

        var valid = PsExecCollectorRunner.TryNormalizePayload(payload, "pc-01.contoso.local", out var error);

        Assert.True(valid, error);
        Assert.NotNull(payload.Device.Ips);
        Assert.NotNull(payload.Profiles);
    }

    [Theory]
    [InlineData("PC-02", "1.2")]
    [InlineData("PC-01", "2.0")]
    public void TryNormalizePayload_RejectsWrongHostOrSchema(string hostname, string schemaVersion)
    {
        var payload = new Models.CollectorPayload
        {
            SchemaVersion = schemaVersion,
            Device = new Models.CollectorDevice { Hostname = hostname }
        };

        Assert.False(PsExecCollectorRunner.TryNormalizePayload(payload, "PC-01", out _));
    }
}
