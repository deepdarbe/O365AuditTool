using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Text.Json;
using O365AuditTool.Models;

namespace O365AuditTool.Services;

public record CollectResult(bool Success, CollectorPayload? Payload, string? ErrorMessage, bool IsOffline);

public interface IRemoteCollectorRunner
{
    Task<CollectResult> RunAsync(string deviceName, CancellationToken cancellationToken);
}

public class PsExecCollectorRunner(IOptions<CollectorOptions> options, ILogger<PsExecCollectorRunner> logger) : IRemoteCollectorRunner
{
    private readonly CollectorOptions _options = options.Value;

    public async Task<CollectResult> RunAsync(string deviceName, CancellationToken cancellationToken)
    {
        if (!File.Exists(_options.PsExecPath))
        {
            return new CollectResult(false, null, $"PsExec not found at '{_options.PsExecPath}'", false);
        }

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = _options.PsExecPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
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
        process.StartInfo.ArgumentList.Add("-File");
        process.StartInfo.ArgumentList.Add(_options.RemoteScriptPath);

        try
        {
            process.Start();
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
                    true);
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (process.ExitCode != 0)
            {
                var error = string.IsNullOrWhiteSpace(stderr) ? "PsExec command failed." : stderr.Trim();
                var offline = error.Contains("network path was not found", StringComparison.OrdinalIgnoreCase) ||
                              error.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
                              error.Contains("could not start", StringComparison.OrdinalIgnoreCase);
                return new CollectResult(false, null, error, offline);
            }

            var json = ExtractJsonObject(stdout);
            if (string.IsNullOrWhiteSpace(json))
            {
                return new CollectResult(false, null, "Collector output did not contain JSON payload.", false);
            }

            var payload = JsonSerializer.Deserialize<CollectorPayload>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (payload is null)
            {
                return new CollectResult(false, null, "Collector JSON could not be parsed.", false);
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

    private static string? ExtractJsonObject(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var start = raw.IndexOf('{');
        var end = raw.LastIndexOf('}');
        if (start < 0 || end <= start)
        {
            return null;
        }

        return raw[start..(end + 1)].Trim();
    }
}
