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

    // Regression guard for the 2026-08 "117 devices offline" incident. The classifier used
    // to test the message text before the exit code, so every authorization failure whose
    // message contained the generic marker "couldn't access" was stored as Offline and
    // retried forever while the real cause stayed invisible.
    [Theory]
    [InlineData(6, "Couldn't access CORELAPP:\nThe handle is invalid.")]
    [InlineData(6, "Couldn't access PC-01:\nAğ yolu bulunamadı.")]
    [InlineData(5, "Couldn't access PC-02: the network path was not found.")]
    [InlineData(1326, "Couldn't access PC-03: logon failure.")]
    [InlineData(1789, "Couldn't access PC-04: trust relationship failed.")]
    [InlineData(1385, "Couldn't access PC-05: timed out.")]
    public void IsOfflineFailure_LetsTheExitCodeOverrideNetworkSoundingText(int exitCode, string error)
    {
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(exitCode, error));
    }

    // A localized endpoint reports ERROR_INVALID_HANDLE with translated text, so the English
    // marker alone cannot classify it; only the exit code can.
    [Theory]
    [InlineData(6, "PC-06 baglanti hatasi: tanitici gecersiz.")]
    [InlineData(6, "")]
    public void IsOfflineFailure_ClassifiesLocalizedInvalidHandleByExitCode(int exitCode, string error)
    {
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(exitCode, error));
    }

    [Theory]
    [InlineData(53, "Couldn't access PC-07: the network path was not found.")]
    [InlineData(1722, "")]
    [InlineData(1231, "")]
    public void IsOfflineFailure_StillTreatsTransientNetworkExitCodesAsOffline(int exitCode, string error)
    {
        Assert.True(PsExecCollectorRunner.IsOfflineFailure(exitCode, error));
    }

    [Fact]
    public void BuildStartInfo_CapturesBothStreamsWithoutCreatingAWindow()
    {
        var startInfo = PsExecCollectorRunner.BuildStartInfo(@"C:\tools\psexec.exe");

        Assert.True(startInfo.RedirectStandardInput);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Equal(@"C:\tools\psexec.exe", startInfo.FileName);
    }

    [Fact]
    public void IsOfflineFailure_TreatsInvalidHandleAsAuthorizationFailure()
    {
        // Root cause of the all-offline incident. PsExec reports a failed connection or
        // authentication as "The handle is invalid." (exit 6): on the customer domain the
        // identical invocation succeeded as an endpoint administrator and failed this way
        // as the management server's machine account, which could not write to ADMIN$.
        // Classifying it as Offline retried it forever and hid the missing endpoint rights.
        Assert.False(PsExecCollectorRunner.IsOfflineFailure(
            6,
            "Couldn't access CORELAPP:\nThe handle is invalid."));
    }

    [Fact]
    public void ExtractJsonObject_StopsAtTheClosingBraceAndIgnoresTrailingText()
    {
        // Taking everything up to the last brace swallowed trailing shell output and
        // produced "Expected depth to be zero at the end of the JSON payload".
        const string raw = "noise before {\"schemaVersion\":\"1.3\",\"device\":{\"hostname\":\"PC-01\"}} " +
                           "PsExec exited on PC-01 with error code 0. {stray}";

        var json = PsExecCollectorRunner.ExtractJsonObject(raw);

        Assert.Equal("{\"schemaVersion\":\"1.3\",\"device\":{\"hostname\":\"PC-01\"}}", json);
    }

    [Fact]
    public void ExtractJsonObject_IgnoresBracesInsideStrings()
    {
        const string raw = "{\"path\":\"C:\\\\Users\\\\{weird}\\\\mail.pst\",\"ok\":true} trailing";

        var json = PsExecCollectorRunner.ExtractJsonObject(raw);

        Assert.Equal("{\"path\":\"C:\\\\Users\\\\{weird}\\\\mail.pst\",\"ok\":true}", json);
    }

    [Fact]
    public void ExtractJsonObject_ReturnsNullWhenTheObjectNeverCloses()
    {
        Assert.Null(PsExecCollectorRunner.ExtractJsonObject("{\"schemaVersion\":\"1.3\",\"device\":"));
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
    public void BuildCollectorEncodedCommand_ForwardsDropBoxAndScanBudget()
    {
        var command = DecodeCollectorCommand(PsExecCollectorRunner.BuildCollectorEncodedCommand(
            @"\\server\share\collector.ps1",
            new string('A', 64),
            @"\\server\o365audit-results",
            scanFixedDrives: true,
            pstScanBudgetSeconds: 90));

        Assert.Contains(@"-OutputPath '\\server\o365audit-results'", command, StringComparison.Ordinal);
        Assert.Contains("-PstScanBudgetSeconds 90", command, StringComparison.Ordinal);
        Assert.DoesNotContain("-SkipFixedDriveScan", command, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildCollectorEncodedCommand_OmitsDropBoxWhenUnsetAndClampsBudget()
    {
        var command = DecodeCollectorCommand(PsExecCollectorRunner.BuildCollectorEncodedCommand(
            @"\\server\share\collector.ps1",
            new string('A', 64),
            resultShareUncPath: string.Empty,
            scanFixedDrives: false,
            pstScanBudgetSeconds: 5000));

        Assert.DoesNotContain("-OutputPath", command, StringComparison.Ordinal);
        Assert.Contains("-SkipFixedDriveScan", command, StringComparison.Ordinal);
        Assert.Contains("-PstScanBudgetSeconds 3600", command, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"\\server\share", true)]
    [InlineData(@"\\server\share\sub", true)]
    [InlineData(@"C:\local\path", false)]
    [InlineData(@"\\server\share'; Remove-Item C:\ -Recurse #", false)]
    [InlineData("\\\\server\\share\r\nWrite-Host hi", false)]
    [InlineData(@"\\server\share$(whoami)", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsUncPath_RejectsAnythingThatCouldEscapeTheQuotedArgument(string? value, bool expected)
    {
        // The value is interpolated into a single-quoted PowerShell string that runs as
        // SYSTEM on every endpoint, so it is rejected rather than escaped.
        Assert.Equal(expected, PsExecCollectorRunner.IsUncPath(value));
    }

    private static string DecodeCollectorCommand(string encoded) =>
        System.Text.Encoding.Unicode.GetString(Convert.FromBase64String(encoded));

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
