using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using O365AuditTool.Services;
using Xunit;

namespace O365AuditTool.Tests;

/// <summary>
/// Covers PsExecCollectorRunner.RunAsync itself - the process path had no coverage at all,
/// although every rule it encodes (exit-code classification, timeout kill, payload extraction,
/// pre-flight reachability) was learned from a production failure. The runner starts the
/// configured binary directly, so the tests point it at PsExecStubExecutable and pass that
/// stub's real hash.
/// </summary>
public class PsExecCollectorRunnerProcessTests
{
    private const string DeviceName = "NBR-PC01";

    // Real PsExec frames the collector output with its own banner and trailer; keeping them
    // around each payload proves RunAsync still finds the object in between.
    private const string PsExecBanner = "\r\nPsExec v2.43 - Execute processes remotely\r\n\r\n";
    private const string PsExecTrailer = "\r\npsexec exited on NBR-PC01 with error code 0.\r\n";

    private const string Payload =
        """{"schemaVersion":"1.3","device":{"hostname":"NBR-PC01.nbr.local","os":"Windows 11 Pro"},"pstFiles":[{"sid":"S-1-5-21-1","path":"C:\\Users\\ada\\archive.pst","sizeBytes":1024}]}""";

    [Fact]
    public async Task RunAsync_ExitZeroWithPayload_ReturnsSuccessAndNormalizesCollections()
    {
        using var stub = PsExecStubExecutable.Exiting(0, PsExecBanner + Payload + PsExecTrailer);

        var result = await CreateRunner(stub).RunAsync(DeviceName, CancellationToken.None);

        Assert.True(result.Success, result.ErrorMessage);
        Assert.Null(result.ErrorMessage);
        Assert.False(result.IsOffline);
        Assert.False(result.IsTimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.NotNull(result.Payload);
        Assert.Equal("NBR-PC01.nbr.local", result.Payload!.Device.Hostname);
        Assert.Equal(@"C:\Users\ada\archive.pst", Assert.Single(result.Payload.PstFiles).Path);
        // Ingestion enumerates every collection, so RunAsync must hand back normalized ones
        // even when the collector omitted them.
        Assert.NotNull(result.Payload.Device.Ips);
        Assert.NotNull(result.Payload.Profiles);
        Assert.NotNull(result.Payload.Errors);
    }

    [Fact]
    public async Task RunAsync_LaunchesPsExecWithConnectTimeoutAndHashPinnedCommand()
    {
        using var stub = PsExecStubExecutable.Exiting(0, Payload);
        var options = CreateOptions(stub);
        options.PsExecConnectTimeoutSeconds = 17;

        var result = await CreateRunner(options).RunAsync(DeviceName, CancellationToken.None);

        Assert.True(result.Success, result.ErrorMessage);
        var arguments = stub.Arguments;
        Assert.Equal(@"\\NBR-PC01", arguments[0]);
        Assert.Contains("-accepteula", arguments);
        Assert.Contains("-h", arguments);
        Assert.Contains("-s", arguments);

        // -n bounds the CONNECT phase only. Without it an unreachable endpoint held its
        // parallel slot for the whole DeviceTimeoutSeconds collector budget.
        var connectTimeout = Array.IndexOf(arguments, "-n");
        Assert.True(connectTimeout >= 0, "PsExec was launched without a connect timeout.");
        Assert.Equal("17", arguments[connectTimeout + 1]);

        // The remote shell must verify the collector before running it; a command that lost
        // the hash would execute whatever sits on the share.
        var command = Encoding.Unicode.GetString(Convert.FromBase64String(arguments[^1]));
        Assert.Contains("Get-FileHash", command, StringComparison.Ordinal);
        Assert.Contains(options.RemoteScriptSha256, command, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(options.RemoteScriptPath, command, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_ExitZeroWithoutJson_KeepsTheRawOutputInTheFailure()
    {
        const string raw = "collector.ps1 cannot be loaded because running scripts is disabled on this system.";
        using var stub = PsExecStubExecutable.Exiting(0, PsExecBanner + raw + PsExecTrailer);

        var result = await CreateRunner(stub).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Null(result.Payload);
        Assert.False(result.IsOffline);
        Assert.False(result.IsTimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Collector output did not contain JSON payload.", result.ErrorMessage!, StringComparison.Ordinal);
        // Without the raw text the operator only sees "no JSON" and cannot tell an
        // execution-policy block from a collector crash or an empty run.
        Assert.Contains(raw, result.ErrorMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_ExitZeroWithUnparsableJson_KeepsTheRawOutputInTheFailure()
    {
        const string raw = """{"schemaVersion":"1.3","device":}""";
        using var stub = PsExecStubExecutable.Exiting(0, PsExecBanner + raw + PsExecTrailer);

        var result = await CreateRunner(stub).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Null(result.Payload);
        Assert.False(result.IsOffline);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Collector JSON could not be parsed", result.ErrorMessage!, StringComparison.Ordinal);
        // Truncated output and interleaved output fail the same way; only the raw text separates them.
        Assert.Contains(raw, result.ErrorMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_PayloadFromAnotherHost_IsRejected()
    {
        const string foreignPayload = """{"schemaVersion":"1.3","device":{"hostname":"NBR-PC42"}}""";
        using var stub = PsExecStubExecutable.Exiting(0, PsExecBanner + foreignPayload + PsExecTrailer);

        var result = await CreateRunner(stub).RunAsync(DeviceName, CancellationToken.None);

        // Storing this payload would file another machine's PST inventory under NBR-PC01.
        Assert.False(result.Success);
        Assert.Null(result.Payload);
        Assert.False(result.IsOffline);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Collector hostname mismatch.", result.ErrorMessage!, StringComparison.Ordinal);
        Assert.Contains("NBR-PC42", result.ErrorMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_AuthorizationExitCode_IsReportedAsErrorNotOffline()
    {
        // Measured on nbr.local in 2026-08: the service ran as LocalSystem, the endpoint saw
        // the machine account, which cannot write ADMIN$, and PsExec reported exit 6. Calling
        // that Offline is what retried 117 endpoints forever while the cause stayed invisible.
        const string standardError = "Couldn't access NBR-PC01:\r\nThe handle is invalid.";
        using var stub = PsExecStubExecutable.Exiting(6, standardError: standardError);

        var result = await CreateRunner(stub).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Null(result.Payload);
        Assert.False(result.IsOffline);
        Assert.False(result.IsTimedOut);
        Assert.Equal(6, result.ExitCode);
        Assert.StartsWith("PsExec exit 6:", result.ErrorMessage!, StringComparison.Ordinal);
        Assert.Contains("The handle is invalid.", result.ErrorMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_TransientNetworkExitCode_IsReportedAsOffline()
    {
        using var stub = PsExecStubExecutable.Exiting(53, standardError: "The network path was not found.");

        var result = await CreateRunner(stub).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.True(result.IsOffline);
        Assert.False(result.IsTimedOut);
        Assert.Equal(53, result.ExitCode);
        Assert.StartsWith("PsExec exit 53:", result.ErrorMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_HangingCollector_TimesOutAndKillsTheProcessTree()
    {
        using var stub = PsExecStubExecutable.Hanging();
        var options = CreateOptions(stub);
        options.DeviceTimeoutSeconds = 2;

        var stopwatch = Stopwatch.StartNew();
        var result = await CreateRunner(options).RunAsync(DeviceName, CancellationToken.None);
        stopwatch.Stop();

        Assert.False(result.Success);
        Assert.True(result.IsTimedOut);
        // A collector that hung is not an unreachable device; the dashboard states differ.
        Assert.False(result.IsOffline);
        Assert.Null(result.ExitCode);
        Assert.Contains("Collector timed out after 2 seconds.", result.ErrorMessage!, StringComparison.Ordinal);
        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(20),
            $"The timeout path took {stopwatch.Elapsed.TotalSeconds:F1}s and must not outlive the device budget.");

        // A surviving PsExec keeps the pipe open and the parallel slot occupied, so the kill
        // has to reach the children too - not only the process the runner started.
        var tree = stub.ProcessTree;
        Assert.Equal(2, tree.Length);
        foreach (var processId in tree)
        {
            await AssertProcessExitedAsync(processId);
        }
    }

    [Fact]
    public async Task RunAsync_UnresolvableDevice_ReportsOfflineWithoutStartingPsExec()
    {
        using var stub = PsExecStubExecutable.Exiting(0, Payload);
        var options = CreateOptions(stub);
        options.ReachabilityProbeEnabled = true;
        options.ReachabilityProbeTimeoutSeconds = 2;
        // RFC 2606 reserves .invalid, so this name resolves nowhere and the probe answers fast.
        var device = $"o365audit-{Guid.NewGuid():N}.invalid";

        var stopwatch = Stopwatch.StartNew();
        var result = await CreateRunner(options).RunAsync(device, CancellationToken.None);
        stopwatch.Stop();

        Assert.False(result.Success);
        Assert.True(result.IsOffline);
        // Offline is now measured, so it must not be reported as a collector that ran too long.
        Assert.False(result.IsTimedOut);
        Assert.Null(result.ExitCode);
        Assert.Contains(
            "Device is unreachable: no answer on TCP 445 within 2 seconds",
            result.ErrorMessage!,
            StringComparison.Ordinal);
        Assert.False(stub.WasStarted, "An unreachable device must fail the probe before a PsExec slot is spent.");
        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(15),
            $"The probe took {stopwatch.Elapsed.TotalSeconds:F1}s; it exists to fail fast.");
    }

    [Fact]
    public async Task RunAsync_TamperedPsExec_IsNeverStarted()
    {
        using var stub = PsExecStubExecutable.Exiting(0, Payload);
        var options = CreateOptions(stub);
        // Correctly shaped, so it passes the format check and only the file content can fail it.
        options.PsExecSha256 = new string('0', 64);

        var result = await CreateRunner(options).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.False(result.IsOffline);
        Assert.Equal("PsExec SHA256 validation failed.", result.ErrorMessage);
        Assert.False(stub.WasStarted, "A binary that failed integrity validation must never run.");
    }

    [Fact]
    public async Task RunAsync_MissingCollectorScriptHash_IsNeverStarted()
    {
        using var stub = PsExecStubExecutable.Exiting(0, Payload);
        var options = CreateOptions(stub);
        options.RemoteScriptSha256 = string.Empty;

        var result = await CreateRunner(options).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.False(result.IsOffline);
        Assert.Equal("Collector script SHA256 is missing or invalid.", result.ErrorMessage);
        // Without a pinned hash the remote shell would run whatever sits on the share.
        Assert.False(stub.WasStarted);
    }

    [Fact]
    public async Task RunAsync_MissingPsExec_FailsWithThePathItLookedFor()
    {
        using var stub = PsExecStubExecutable.Exiting(0, Payload);
        var options = CreateOptions(stub);
        options.PsExecPath = Path.Combine(Path.GetDirectoryName(stub.ExecutablePath)!, "absent.exe");

        var result = await CreateRunner(options).RunAsync(DeviceName, CancellationToken.None);

        Assert.False(result.Success);
        Assert.False(result.IsOffline);
        Assert.StartsWith("PsExec not found at", result.ErrorMessage!, StringComparison.Ordinal);
        Assert.Contains(options.PsExecPath, result.ErrorMessage!, StringComparison.Ordinal);
    }

    private static CollectorOptions CreateOptions(PsExecStubExecutable stub) => new()
    {
        PsExecPath = stub.ExecutablePath,
        PsExecSha256 = stub.Sha256,
        RemoteScriptPath = @"\\filesrv\audit\collector.ps1",
        RemoteScriptSha256 = new string('a', 64),
        DeviceTimeoutSeconds = 30,
        PsExecConnectTimeoutSeconds = 5,
        // The stub runs locally while the device name is fictional, so the SMB probe would
        // fail every process-path case before it started. The probe has its own test.
        ReachabilityProbeEnabled = false
    };

    private static PsExecCollectorRunner CreateRunner(PsExecStubExecutable stub) => CreateRunner(CreateOptions(stub));

    private static PsExecCollectorRunner CreateRunner(CollectorOptions options) =>
        new(Options.Create(options), NullLogger<PsExecCollectorRunner>.Instance);

    private static async Task AssertProcessExitedAsync(int processId)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (!IsRunning(processId))
            {
                return;
            }

            await Task.Delay(100);
        }

        Assert.Fail($"Process {processId} outlived the collector timeout, so the PsExec process tree was not killed.");
    }

    private static bool IsRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
