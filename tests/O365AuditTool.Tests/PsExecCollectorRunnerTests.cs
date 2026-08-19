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
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(1, "Couldn't access PC-01: Access is denied."));
    }

    [Fact]
    public void ComposeFailureDetail_PrefersStderrAndAppendsStdout()
    {
        var detail = PsExecCollectorRunner.ComposeFailureDetail(
            "collector diagnostic line",
            "Couldn't access PC-01: Access is denied.");

        Assert.StartsWith("Couldn't access PC-01: Access is denied.", detail);
        Assert.Contains("stdout: collector diagnostic line", detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, null, "PsExec produced no diagnostic output.")]
    [InlineData("   ", "", "PsExec produced no diagnostic output.")]
    public void ComposeFailureDetail_FallsBackWhenBothStreamsEmpty(string? stdout, string? stderr, string expected)
    {
        Assert.Equal(expected, PsExecCollectorRunner.ComposeFailureDetail(stdout, stderr));
    }

    [Fact]
    public void ComposeFailureDetail_UsesStdoutWhenStderrEmpty()
    {
        var detail = PsExecCollectorRunner.ComposeFailureDetail("Access is denied.", "");

        Assert.Equal("stdout: Access is denied.", detail);
        // A version that writes the reason to stdout must still classify correctly.
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(1, detail));
    }

    [Fact]
    public void TryVerifyFileHash_RejectsTamperedExecutable()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "trusted");
            var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
            Assert.True(PsExecCollectorRunner.TryVerifyFileHash(path, expected, out var initialError), initialError);

            File.WriteAllText(path, "tampered");
            Assert.False(PsExecCollectorRunner.TryVerifyFileHash(path, expected, out var error));
            Assert.Equal("PsExec SHA256 validation failed.", error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void BuildCollectorEncodedCommand_PinsScriptHash()
    {
        var expected = new string('A', 64);
        var encoded = PsExecCollectorRunner.BuildCollectorEncodedCommand(
            "\\\\server\\share\\collector.ps1",
            expected);
        var command = System.Text.Encoding.Unicode.GetString(Convert.FromBase64String(encoded));

        Assert.Contains("Get-FileHash", command, StringComparison.Ordinal);
        Assert.Contains(expected, command, StringComparison.Ordinal);
        Assert.Contains("\\\\server\\share\\collector.ps1", command, StringComparison.Ordinal);
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
