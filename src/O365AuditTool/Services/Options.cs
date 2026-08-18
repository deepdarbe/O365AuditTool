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
