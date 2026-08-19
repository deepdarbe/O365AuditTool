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

        using var process = new Process
        {
            StartInfo = BuildStartInfo(_options.PsExecPath)
        };

        process.StartInfo.ArgumentList.Add($"\\\\{deviceName}");
        process.StartInfo.ArgumentList.Add("-nobanner");
        process.StartInfo.ArgumentList.Add("-accepteula");
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
                return new CollectResult(
                    false,
                    null,
                    $"Collector timed out after {_options.DeviceTimeoutSeconds} seconds.",
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
                    false);
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
                    false);
            }

            if (payload is null)
            {
                return new CollectResult(false, null, "Collector JSON could not be parsed.", false);
            }

            if (!TryNormalizePayload(payload, deviceName, out var payloadError))
            {
                return new CollectResult(false, null, payloadError, false);
            }

            return new CollectResult(true, payload, null, false);
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

    internal static bool IsOfflineFailure(int exitCode, string error)
    {
        if (error.Contains("access is denied", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("erişim engellendi", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("erişim reddedildi", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // PsExec reports a failed connection or authentication as
        // "Couldn't access <host>: The handle is invalid." (exit 6). Measured on a customer
        // domain: the same invocation succeeded as an endpoint administrator and failed this
        // way as the management server's machine account, which could not write to the
        // endpoint ADMIN$. It is an authorization failure, so it must classify as Error —
        // retrying it as Offline only hides that the service identity lacks endpoint rights.
        if (error.Contains("handle is invalid", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int[] transientNetworkCodes = [53, 64, 67, 121, 1231, 1232, 1460, 1722, 1726];
        if (transientNetworkCodes.Contains(exitCode))
        {
            return true;
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
