namespace O365AuditTool.Services;

public class CollectorOptions
{
    public string PsExecPath { get; set; } = "C:\\Tools\\PsExec\\psexec.exe";
    public string PsExecSha256 { get; set; } = string.Empty;
    public string RemoteScriptPath { get; set; } = "\\\\filesrv\\audit\\collector.ps1";
    public string RemoteScriptSha256 { get; set; } = string.Empty;
    public int DeviceTimeoutSeconds { get; set; } = 300;
    public int MaxDeviceParallelism { get; set; } = 4;
    public int JobPollingSeconds { get; set; } = 10;
    public int DailyRunHour { get; set; } = 2;
    public int DailyRunMinute { get; set; } = 15;
    public int[] RetryMinutes { get; set; } = [30, 120, 1440];
    public int ExcludeComputersInactiveDays { get; set; } = 120;
    public string[] FallbackTargets { get; set; } = [];
    public string? DefaultOuFilter { get; set; }
    public string? DefaultSiteFilter { get; set; }
}

public class AuthOptions
{
    public Dictionary<string, string[]> RoleMappings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public class CopyOptions
{
    public bool Enabled { get; set; }
    public string DefaultTargetRoot { get; set; } = string.Empty;
    public string[] AllowedTargetRoots { get; set; } = [];
    public string[] AllowedSourceUncRoots { get; set; } = [];
    public int MaxParallelism { get; set; } = 2;
    public int BufferSizeMb { get; set; } = 4;
    public bool VerifySha256 { get; set; } = true;
    public int MaxAttempts { get; set; } = 2;
    public int PollingSeconds { get; set; } = 5;
}

/// <summary>
/// Build version of the running application, surfaced in the dashboard so an operator can
/// confirm which build is actually serving before trusting or re-running a scan.
/// </summary>
public static class AppVersion
{
    public static string Current { get; } = ResolveVersion();

    private static string ResolveVersion()
    {
        var assembly = typeof(AppVersion).Assembly;
        var informational = assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?
            .InformationalVersion;

        var value = string.IsNullOrWhiteSpace(informational)
            ? assembly.GetName().Version?.ToString()
            : informational;

        if (string.IsNullOrWhiteSpace(value))
        {
            return "unknown";
        }

        // Strip the "+<commit sha>" source-revision suffix the SDK appends.
        var plus = value.IndexOf('+');
        return plus > 0 ? value[..plus] : value;
    }
}
