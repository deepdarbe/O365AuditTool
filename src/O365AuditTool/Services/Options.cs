namespace O365AuditTool.Services;

public class CollectorOptions
{
    public string PsExecPath { get; set; } = "C:\\Tools\\PsExec\\psexec.exe";
    public string RemoteScriptPath { get; set; } = "\\\\filesrv\\audit\\collector.ps1";
    public string RemoteTempJsonPath { get; set; } = "C:\\Windows\\Temp\\o365-audit.json";
    public int DeviceTimeoutSeconds { get; set; } = 300;
    public int MaxDeviceParallelism { get; set; } = 4;
    public int JobPollingSeconds { get; set; } = 10;
    public int DailyRunHour { get; set; } = 2;
    public int DailyRunMinute { get; set; } = 15;
    public int[] RetryMinutes { get; set; } = [30, 120, 1440];
    public string[] FallbackTargets { get; set; } = [];
    public string? DefaultOuFilter { get; set; }
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
    public int MaxParallelism { get; set; } = 2;
    public int BufferSizeMb { get; set; } = 4;
    public bool VerifySha256 { get; set; }
    public int MaxAttempts { get; set; } = 2;
    public int PollingSeconds { get; set; } = 5;
}
