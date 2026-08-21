namespace O365AuditTool.Services;

public class CollectorOptions
{
    public string PsExecPath { get; set; } = "C:\\Tools\\PsExec\\psexec.exe";
    public string PsExecSha256 { get; set; } = string.Empty;
    public string RemoteScriptPath { get; set; } = "\\\\filesrv\\audit\\collector.ps1";
    public string RemoteScriptSha256 { get; set; } = string.Empty;
    public int DeviceTimeoutSeconds { get; set; } = 300;

    /// <summary>
    /// PsExec <c>-n</c> connect timeout. Bounds only the CONNECT phase, never the
    /// collector run itself, so an unreachable endpoint releases its parallel slot
    /// instead of waiting out <see cref="DeviceTimeoutSeconds"/>.
    /// </summary>
    public int PsExecConnectTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Probe SMB (445) before spending a PsExec slot. An unreachable device then fails
    /// as a measured Offline instead of an inferred one (the 2026-08 "117 offline"
    /// incident classified authorization failures as Offline because nothing measured
    /// reachability).
    /// </summary>
    public bool ReachabilityProbeEnabled { get; set; } = true;
    public int ReachabilityProbePort { get; set; } = 445;
    public int ReachabilityProbeTimeoutSeconds { get; set; } = 5;

    public int MaxDeviceParallelism { get; set; } = 4;
    public int JobPollingSeconds { get; set; } = 10;
    public int DailyRunHour { get; set; } = 2;
    public int DailyRunMinute { get; set; } = 15;
    public int[] RetryMinutes { get; set; } = [30, 120, 1440];
    public int ExcludeComputersInactiveDays { get; set; } = 120;
    public string[] FallbackTargets { get; set; } = [];
    public string? DefaultOuFilter { get; set; }
    public string? DefaultSiteFilter { get; set; }

    /// <summary>
    /// Device-name exclusions, matched case-insensitively and supporting <c>*</c>/<c>?</c>
    /// wildcards (for example <c>NAS*</c>).
    /// </summary>
    public string[] ExcludeDeviceNames { get; set; } = [];

    /// <summary>
    /// Distinguished names whose subtree is excluded, for example
    /// <c>OU=SERVER,DC=nbr,DC=local</c>.
    /// </summary>
    public string[] ExcludeOus { get; set; } = [];

    /// <summary>Skip computer objects whose operatingSystem contains "Server".</summary>
    public bool ExcludeServerOperatingSystems { get; set; } = true;

    /// <summary>Skip domain controllers and read-only domain controllers (primaryGroupID 516/521).</summary>
    public bool ExcludeDomainControllers { get; set; } = true;

    /// <summary>
    /// Skip computer objects with no operatingSystem attribute. Domain-joined appliances
    /// (Synology/NAS, Samba) present this way and can never run the collector. Defaults to
    /// OFF: a missing attribute is a hint, not a fact, and a stale-but-real workstation would
    /// otherwise be dropped without ever appearing in a result. Turn it on per environment
    /// once the appliances have been identified (nbr.local does).
    /// </summary>
    public bool ExcludeUnknownOperatingSystem { get; set; }

    /// <summary>
    /// UNC path of the write-only drop box the collector writes its JSON result to. The
    /// 2026-03 deployment that actually worked wrote results to a share and used the remote
    /// console only as a control channel; carrying the whole payload back over PsExec stdout
    /// is what turned one stray line or one code-page mismatch into "no JSON payload" for a
    /// device. Empty keeps the stdout-only behaviour.
    /// </summary>
    public string ResultShareUncPath { get; set; } = string.Empty;

    /// <summary>
    /// Local path of <see cref="ResultShareUncPath"/> on this server. Result files are read
    /// and deleted locally; the file name reported by the endpoint is never used as a path.
    /// </summary>
    public string ResultLocalPath { get; set; } = string.Empty;

    /// <summary>
    /// Search every non-system fixed drive for PST archives. Detached archives on D:/E: are
    /// the ones a migration has to account for, and they are invisible to a registry-only
    /// scan because no Outlook profile references them any more.
    /// </summary>
    public bool PstScanFixedDrives { get; set; } = true;

    /// <summary>
    /// Wall-clock budget for the collector's file-system PST search, in seconds. The search
    /// stops when the budget is spent and records how far it got, so a device with a large
    /// data drive degrades to partial results instead of consuming its whole scan slot.
    /// </summary>
    public int PstScanBudgetSeconds { get; set; } = 120;
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
