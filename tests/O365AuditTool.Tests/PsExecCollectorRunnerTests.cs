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

    [Theory]
    [InlineData(5, "Access is denied.")]
    [InlineData(1, "Couldn't access PC-01: Access is denied.")]
    [InlineData(5, "Erişim reddedildi.")]
    [InlineData(5, "Erişim engellendi.")]
    public void IsOfflineFailure_DoesNotRetryAuthorizationFailures(int exitCode, string error)
    {
        // Localized authorization text must classify as Error (not Offline) once the
        // OEM console encoding delivers it intact.
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(exitCode, error));
    }

    [Fact]
    public void BuildStartInfo_AllocatesAConsoleForPsExec()
    {
        // Regression for the all-offline incident: PsExec requires a real console.
        // Launched from the session-0 service with CreateNoWindow=true it fails before
        // reaching the endpoint with "Couldn't access <host>: The handle is invalid."
        // (exit 6) — verified as SYSTEM on the customer's server, where the identical
        // invocation with an allocated console returned exit 0. CreateNoWindow MUST stay
        // false so CreateProcess allocates a hidden conhost for PsExec.
        var startInfo = PsExecCollectorRunner.BuildStartInfo(@"C:\tools\psexec.exe");

        Assert.True(startInfo.RedirectStandardInput);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.False(startInfo.UseShellExecute);
        Assert.False(startInfo.CreateNoWindow);
        Assert.Equal(@"C:\tools\psexec.exe", startInfo.FileName);
    }

    [Fact]
    public void IsOfflineFailure_TreatsInvalidHandleAsOffline_DocumentingTheReportedSymptom()
    {
        // Exit 6 with "Couldn't access" matched the generic network marker, which is why
        // 117/118 powered-on endpoints were reported Offline instead of surfacing the real
        // handle defect. Kept as documentation of the observed customer text.
        Assert.True(PsExecCollectorRunner.IsOfflineFailure(
            6,
            "Couldn't access CORELAPP:\nThe handle is invalid."));
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
