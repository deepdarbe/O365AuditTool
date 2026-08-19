using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using O365AuditTool.Models;

namespace O365AuditTool.Services;

public record CollectResult(
    bool Success,
    CollectorPayload? Payload,
    string? ErrorMessage,
    bool IsOffline,
    bool IsTimedOut = false,
    int? ExitCode = null);

public interface IRemoteCollectorRunner
{
    Task<CollectResult> RunAsync(string deviceName, CancellationToken cancellationToken);
}

public class PsExecCollectorRunner(IOptions<CollectorOptions> options, ILogger<PsExecCollectorRunner> logger) : IRemoteCollectorRunner
{
    private readonly CollectorOptions _options = options.Value;

    // PsExec is a native console app that emits localized status/error text using the
    // host's OEM console code page (e.g. CP857 on Turkish Windows). If .NET decodes the
    // redirected streams with the wrong code page, localized markers such as
    // "Erişim reddedildi" or "Ağ yolu bulunamadı" are mangled and IsOfflineFailure cannot
    // match them. Pinning the stream encoding to the OEM code page fixes that.
    private static readonly Encoding? ConsoleOutputEncoding = ResolveConsoleOutputEncoding();

    private static Encoding? ResolveConsoleOutputEncoding()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var oemCodePage = CultureInfo.CurrentCulture.TextInfo.OEMCodePage;
            return oemCodePage > 0 ? Encoding.GetEncoding(oemCodePage) : null;
        }
        catch (Exception)
        {
            // Fall back to the default stream encoding rather than failing collection.
            return null;
        }
    }

    public async Task<CollectResult> RunAsync(string deviceName, CancellationToken cancellationToken)
    {
        if (!File.Exists(_options.PsExecPath))
        {
            return new CollectResult(false, null, $"PsExec not found at '{_options.PsExecPath}'", false);
        }
        if (!TryVerifyFileHash(_options.PsExecPath, _options.PsExecSha256, out var integrityError))
        {
            logger.LogError("PsExec integrity validation failed: {IntegrityError}", integrityError);
            return new CollectResult(false, null, integrityError, false);
        }
        if (!IsSha256(_options.RemoteScriptSha256))
        {
            return new CollectResult(false, null, "Collector script SHA256 is missing or invalid.", false);
        }

        // Offline must be MEASURED, not inferred from PsExec error text afterwards. Probing
        // the SMB port PsExec itself needs gives a deterministic answer in seconds and keeps
        // authorization failures (which do reach the port) from ever looking like Offline.
        if (_options.ReachabilityProbeEnabled)
        {
            var probe = await ProbeSmbAsync(deviceName, cancellationToken);
            if (!probe.Reachable)
            {
                return new CollectResult(
                    false,
                    null,
                    $"Device is unreachable: no answer on TCP {_options.ReachabilityProbePort} within " +
                    $"{Math.Clamp(_options.ReachabilityProbeTimeoutSeconds, 1, 120)} seconds ({probe.Detail}).",
                    true);
            }
        }

        using var process = new Process
        {
            StartInfo = BuildStartInfo(_options.PsExecPath)
        };

        process.StartInfo.ArgumentList.Add($"\\\\{deviceName}");
        process.StartInfo.ArgumentList.Add("-nobanner");
        process.StartInfo.ArgumentList.Add("-accepteula");
        // -n bounds only the CONNECT phase. Without it an unreachable endpoint holds its
        // parallel slot until DeviceTimeoutSeconds, which is the collector budget, not a
        // connect budget. The proven 2026-03 deployment script used -n 30 for this reason.
        process.StartInfo.ArgumentList.Add("-n");
        process.StartInfo.ArgumentList.Add(
            Math.Clamp(_options.PsExecConnectTimeoutSeconds, 1, 600).ToString(CultureInfo.InvariantCulture));
        process.StartInfo.ArgumentList.Add("-h");
        process.StartInfo.ArgumentList.Add("-s");
        process.StartInfo.ArgumentList.Add("powershell");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-EncodedCommand");
        process.StartInfo.ArgumentList.Add(BuildCollectorEncodedCommand(
            _options.RemoteScriptPath,
            _options.RemoteScriptSha256));

        try
        {
            process.Start();
            // PsExec only needs a valid stdin handle, never any input. Close it so the
            // remote process cannot block waiting on the pipe.
            process.StandardInput.Close();
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _options.DeviceTimeoutSeconds)));

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                await KillProcessTreeAsync(process, deviceName);

                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                logger.LogWarning(
                    "Collector timed out after {TimeoutSeconds} seconds for {Device}",
                    _options.DeviceTimeoutSeconds,
                    deviceName);

                // Whatever PsExec already printed tells the operator WHICH phase hung
                // (connect, PSEXESVC install, or the collector itself). Killing the tree
                // closes the pipes, so the readers complete; the grace period only guards
                // against a stuck handle and never blocks the scan.
                var timeoutDetail = await ReadStreamsWithGraceAsync(stdoutTask, stderrTask);
                return new CollectResult(
                    false,
                    null,
                    $"Collector timed out after {_options.DeviceTimeoutSeconds} seconds. {timeoutDetail}",
                    false,
                    true);
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (process.ExitCode != 0)
            {
                // PsExec surfaces the true failure reason in different streams across
                // versions, so classify and persist stdout as well as stderr. The exit
                // code is kept in the message so operators can prove the exact failure
                // (e.g. 53 network path vs 5 access denied) from the dashboard alone.
                var detail = ComposeFailureDetail(stdout, stderr);
                var offline = IsOfflineFailure(process.ExitCode, detail);
                var error = $"PsExec exit {process.ExitCode}: {detail}";
                return new CollectResult(false, null, error, offline, ExitCode: process.ExitCode);
            }

            var json = ExtractJsonObject(stdout);
            if (string.IsNullOrWhiteSpace(json))
            {
                // PsExec succeeded but the collector produced no payload. Keep what it did
                // write: without it the operator only sees "no JSON" and cannot tell a
                // collector crash from an execution-policy block or an empty run.
                return new CollectResult(
                    false,
                    null,
                    $"Collector output did not contain JSON payload. {ComposeFailureDetail(stdout, stderr)}",
                    false,
                    ExitCode: process.ExitCode);
            }

            CollectorPayload? payload;
            try
            {
                payload = JsonSerializer.Deserialize<CollectorPayload>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            }
            catch (JsonException ex)
            {
                // Truncated or interleaved output; the raw text is the only way to tell which.
                return new CollectResult(
                    false,
                    null,
                    $"Collector JSON could not be parsed: {ex.Message} {ComposeFailureDetail(stdout, stderr)}",
                    false,
                    ExitCode: process.ExitCode);
            }

            if (payload is null)
            {
                return new CollectResult(false, null, "Collector JSON could not be parsed.", false, ExitCode: process.ExitCode);
            }

            if (!TryNormalizePayload(payload, deviceName, out var payloadError))
            {
                return new CollectResult(false, null, payloadError, false, ExitCode: process.ExitCode);
            }

            return new CollectResult(true, payload, null, false, ExitCode: process.ExitCode);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Collector run failed for {Device}", deviceName);
            return new CollectResult(false, null, ex.Message, false);
        }
    }

    private async Task KillProcessTreeAsync(Process process, string deviceName)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                using var killWaitCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await process.WaitForExitAsync(killWaitCts.Token);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to kill timed-out PsExec process for {Device}", deviceName);
        }
    }

    internal static ProcessStartInfo BuildStartInfo(string psExecPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = psExecPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // PsExec needs input available; the stream is closed right after start so the
            // remote process never waits on it.
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (ConsoleOutputEncoding is not null)
        {
            startInfo.StandardOutputEncoding = ConsoleOutputEncoding;
            startInfo.StandardErrorEncoding = ConsoleOutputEncoding;
        }

        return startInfo;
    }

    internal static string ComposeFailureDetail(string? stdout, string? stderr)
    {
        const int maxStreamLength = 1500;
        var err = stderr?.Trim();
        var @out = stdout?.Trim();
        var hasErr = !string.IsNullOrWhiteSpace(err);
        var hasOut = !string.IsNullOrWhiteSpace(@out);

        if (hasErr && hasOut)
        {
            return $"{Bound(err!, maxStreamLength)} | stdout: {Bound(@out!, maxStreamLength)}";
        }
        if (hasErr)
        {
            return Bound(err!, maxStreamLength);
        }
        if (hasOut)
        {
            return $"stdout: {Bound(@out!, maxStreamLength)}";
        }
        return "PsExec produced no diagnostic output.";
    }

    private static string Bound(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    internal readonly record struct ReachabilityProbeResult(bool Reachable, string Detail);

    /// <summary>
    /// Opens a TCP connection to the SMB port PsExec depends on. A refused connection still
    /// counts as reachable: the host answered, so the device is not offline and the failure
    /// belongs to a later stage (firewall policy, service state, authorization).
    /// </summary>
    private async Task<ReachabilityProbeResult> ProbeSmbAsync(string deviceName, CancellationToken cancellationToken)
    {
        var port = _options.ReachabilityProbePort is > 0 and <= 65535 ? _options.ReachabilityProbePort : 445;
        var primary = await ProbePortAsync(deviceName, port, cancellationToken);
        if (primary.Reachable || port != 445)
        {
            return primary;
        }

        // PsExec reaches ADMIN$ over SMB direct (445) or NetBIOS (139). Declaring a device
        // offline on 445 alone would mislabel an old endpoint that only listens on 139.
        var legacy = await ProbePortAsync(deviceName, 139, cancellationToken);
        return legacy.Reachable
            ? legacy with { Detail = $"{legacy.Detail} on 139" }
            : primary;
    }

    private async Task<ReachabilityProbeResult> ProbePortAsync(string deviceName, int port, CancellationToken cancellationToken)
    {
        var timeout = TimeSpan.FromSeconds(Math.Clamp(_options.ReachabilityProbeTimeoutSeconds, 1, 120));

        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCts.CancelAfter(timeout);

        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(deviceName, port, probeCts.Token);
            return new ReachabilityProbeResult(true, "connected");
        }
        catch (System.Net.Sockets.SocketException ex)
            when (ex.SocketErrorCode is System.Net.Sockets.SocketError.ConnectionRefused
                or System.Net.Sockets.SocketError.ConnectionReset)
        {
            return new ReachabilityProbeResult(true, $"port closed ({ex.SocketErrorCode})");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // Deliberately not the word "timed out": this is an unreachable device, and the dashboard
            // classifies a timeout as a collector that ran too long, which is a different failure.
            return new ReachabilityProbeResult(false, "no response");
        }
        catch (Exception ex)
        {
            return new ReachabilityProbeResult(false, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Collects whatever the already-started stream readers produced, bounded by a short
    /// grace period so a stuck pipe handle can never hold the device slot open.
    /// </summary>
    private static async Task<string> ReadStreamsWithGraceAsync(Task<string> stdoutTask, Task<string> stderrTask)
    {
        try
        {
            var both = Task.WhenAll(stdoutTask, stderrTask);
            var completed = await Task.WhenAny(both, Task.Delay(TimeSpan.FromSeconds(3)));
            if (completed != both)
            {
                return "PsExec output was not readable before the timeout grace period elapsed.";
            }

            return ComposeFailureDetail(
                stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : string.Empty,
                stderrTask.IsCompletedSuccessfully ? stderrTask.Result : string.Empty);
        }
        catch (Exception)
        {
            // Diagnostics must never turn a timeout into a different failure.
            return "PsExec output could not be read after the timeout.";
        }
    }

    // Windows system error codes PsExec returns when the connection or the service-install
    // step was refused. Measured on nbr.local in 2026-08: the management service ran as
    // LocalSystem, so the endpoint saw the machine account, which cannot write ADMIN$, and
    // PsExec reported that as exit 6 "Couldn't access <host>: The handle is invalid.".
    // These are authorization failures, never transient — retrying them only hides the cause.
    private static readonly int[] AuthorizationExitCodes =
    [
        5,    // ERROR_ACCESS_DENIED
        6,    // ERROR_INVALID_HANDLE (PsExec's report for a refused ADMIN$/IPC$ session)
        1311, // ERROR_NO_LOGON_SERVERS
        1326, // ERROR_LOGON_FAILURE
        1327, // ERROR_ACCOUNT_RESTRICTION
        1331, // ERROR_ACCOUNT_DISABLED
        1385, // ERROR_LOGON_TYPE_NOT_GRANTED
        1789  // ERROR_TRUSTED_RELATIONSHIP_FAILURE
    ];

    private static readonly int[] TransientNetworkExitCodes =
        [53, 64, 67, 121, 1231, 1232, 1460, 1722, 1726];

    internal static bool IsOfflineFailure(int exitCode, string error)
    {
        // The exit code decides first and the text only breaks ties. The previous order was
        // text-first, so any authorization failure whose message happened to contain the
        // generic marker "couldn't access" was stored as Offline and retried forever. That
        // is exactly how 117 endpoints were reported Offline in 2026-08 while the real cause
        // (the service identity could not write ADMIN$) never surfaced anywhere.
        if (AuthorizationExitCodes.Contains(exitCode))
        {
            return false;
        }

        if (TransientNetworkExitCodes.Contains(exitCode))
        {
            return true;
        }

        if (error.Contains("access is denied", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("erişim engellendi", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("erişim reddedildi", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Localized builds report ERROR_INVALID_HANDLE with a translated message, so the
        // English text alone is not enough; the code check above covers the localized case.
        if (error.Contains("handle is invalid", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("tanıtıcı geçersiz", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("oturum açma", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("logon failure", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("trust relationship", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string[] markers =
        [
            "network path was not found",
            "network name is no longer available",
            "network location cannot be reached",
            "no such host is known",
            "host is unreachable",
            "rpc server is unavailable",
            "timed out",
            "could not start",
            "couldn't access",
            "ağ yolu bulunamadı",
            "rpc sunucusu kullanılamıyor",
            "ana bilgisayar bilinmiyor"
        ];
        return markers.Any(marker => error.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool TryVerifyFileHash(string path, string expectedSha256, out string error)
    {
        if (!IsSha256(expectedSha256))
        {
            error = "PsExec SHA256 is missing or invalid.";
            return false;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var actual = Convert.ToHexString(SHA256.HashData(stream));
            if (!actual.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                error = "PsExec SHA256 validation failed.";
                return false;
            }

            error = string.Empty;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = $"PsExec could not be verified: {ex.Message}";
            return false;
        }
    }

    internal static string BuildCollectorEncodedCommand(string scriptPath, string expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(scriptPath) || !IsSha256(expectedSha256))
        {
            throw new ArgumentException("Collector path and a valid SHA256 are required.");
        }

        var escapedPath = scriptPath.Replace("'", "''", StringComparison.Ordinal);
        var command =
            $"$p='{escapedPath}';$e='{expectedSha256.ToUpperInvariant()}';" +
            "$a=(Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash;" +
            "if(-not [String]::Equals($a,$e,[StringComparison]::OrdinalIgnoreCase)){throw 'Collector integrity validation failed.'};& $p";
        return Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    internal static bool TryNormalizePayload(
        CollectorPayload payload,
        string expectedDeviceName,
        out string error)
    {
        if (payload.Device is null || string.IsNullOrWhiteSpace(payload.Device.Hostname))
        {
            error = "Collector payload does not contain a device hostname.";
            return false;
        }

        var expectedHost = expectedDeviceName.Trim().TrimStart('\\').Split('.')[0];
        var reportedHost = payload.Device.Hostname.Trim().Split('.')[0];
        if (!string.Equals(expectedHost, reportedHost, StringComparison.OrdinalIgnoreCase))
        {
            error = $"Collector hostname mismatch. Expected '{expectedDeviceName}', received '{payload.Device.Hostname}'.";
            return false;
        }

        var majorVersion = payload.SchemaVersion?.Split('.')[0];
        if (!string.Equals(majorVersion, "1", StringComparison.Ordinal))
        {
            error = $"Unsupported collector schema version '{payload.SchemaVersion ?? "missing"}'.";
            return false;
        }

        payload.Device.Hostname = payload.Device.Hostname.Trim();
        payload.Device.Ips ??= [];
        payload.Storage ??= new CollectorStorage();
        payload.Storage.Volumes ??= [];
        payload.Storage.Disks ??= [];
        payload.Office ??= new CollectorOffice();
        payload.Office.InstalledProducts ??= [];
        payload.Office.RunningProcesses ??= [];
        payload.Profiles ??= [];
        payload.MailAccounts ??= [];
        payload.PstFiles ??= [];
        payload.LegacyFiles ??= [];
        payload.ScanMeta ??= new CollectorScanMeta();
        payload.Errors ??= [];

        error = string.Empty;
        return true;
    }

    internal static string? ExtractJsonObject(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var start = raw.IndexOf('{');
        if (start < 0)
        {
            return null;
        }

        // Taking everything up to the LAST brace swallowed any trailing text the remote
        // shell appended, producing "Expected depth to be zero" instead of a payload.
        // Track brace depth instead, ignoring braces inside strings, and stop at the object
        // that actually closes.
        var depth = 0;
        var inString = false;
        var escaped = false;

        for (var index = start; index < raw.Length; index++)
        {
            var current = raw[index];

            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (current == '\\')
                {
                    escaped = true;
                }
                else if (current == '"')
                {
                    inString = false;
                }

                continue;
            }

            switch (current)
            {
                case '"':
                    inString = true;
                    break;
                case '{':
                    depth++;
                    break;
                case '}':
                    depth--;
                    if (depth == 0)
                    {
                        return raw[start..(index + 1)].Trim();
                    }

                    break;
            }
        }

        return null;
    }
}
