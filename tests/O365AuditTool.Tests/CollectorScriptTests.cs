using System.Diagnostics;
using Xunit;

namespace O365AuditTool.Tests;

public class CollectorScriptTests
{
    [Fact]
    public void ProfileSidAndDiskClassification_AreConservative()
    {
        var output = InvokeCollectorFunctions(
            "@(" +
            "(Test-UserProfileSid 'S-1-5-21-1-2-3-1001')," +
            "(Test-UserProfileSid 'S-1-12-1-1-2-3-4')," +
            "(Test-UserProfileSid 'S-1-5-18')," +
            "(Convert-ToMediaType -InterfaceType 'SAS' -Model 'Disk' -MediaHint 'HDD' -BusType 'SAS')," +
            "(Convert-ToMediaType -InterfaceType 'SATA' -Model 'Disk' -MediaHint 'HDD' -BusType 'SATA')," +
            "(Convert-ToMediaType -InterfaceType 'NVMe' -Model 'Disk' -MediaHint 'Unknown' -BusType 'NVMe')," +
            "(Convert-ToBusType -InterfaceType 'SATA' -Model 'Disk' -BusType 'SATA')" +
            ") -join '|'"
        );

        Assert.Equal("True|True|False|HDD|HDD|SSD|SATA", output);
    }

    [Fact]
    public void AccountResolution_UsesProfileThenOnlySingleSidFallback()
    {
        var output = InvokeCollectorFunctions(
            "$accounts = @(" +
            "[pscustomobject]@{ sid='S'; profileName='Primary'; address='primary@example.com' }," +
            "[pscustomobject]@{ sid='S'; profileName='Archive'; address='archive@example.com' }," +
            "[pscustomobject]@{ sid='T'; profileName='Only'; address='only@example.com' }" +
            "); " +
            "$exact = Resolve-AccountAddress -Accounts $accounts -Sid 'S' -ProfileName 'Primary'; " +
            "$ambiguous = Resolve-AccountAddress -Accounts $accounts -Sid 'S' -ProfileName 'Missing'; " +
            "$single = Resolve-AccountAddress -Accounts $accounts -Sid 'T' -ProfileName $null; " +
            "@($exact, $(if ($null -eq $ambiguous) { '<null>' } else { $ambiguous }), $single) -join '|'"
        );

        Assert.Equal("primary@example.com|<null>|only@example.com", output);
    }

    [Fact]
    public void DeploymentDnsValidation_AcceptsExactAndSingleLabelWildcardOnly()
    {
        var output = InvokePowerShellFunctions(
            "scripts\\Deploy-ManagementServer.ps1",
            "@(" +
            "(Resolve-DashboardDnsName 'Audit.CONTOSO.local.')," +
            "(Test-CertificateDnsName '*.contoso.local' 'audit.contoso.local')," +
            "(Test-CertificateDnsName '*.contoso.local' 'nested.audit.contoso.local')" +
            ") -join '|'"
        );

        Assert.Equal("audit.contoso.local|True|False", output);
    }

    [Fact]
    public void DeploymentDirectoryCreation_AppliesProtectedAcl()
    {
        var path = Path.Combine(Path.GetTempPath(), $"o365audit-acl-{Guid.NewGuid():N}");
        var escapedPath = path.Replace("'", "''", StringComparison.Ordinal);
        try
        {
            var output = InvokePowerShellFunctions(
                "scripts\\Deploy-ManagementServer.ps1",
                "$admin = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); " +
                "$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18'); " +
                "$current = [Security.Principal.WindowsIdentity]::GetCurrent().User; " +
                $"Initialize-ManagedDirectory -Path '{escapedPath}' -AdministratorsSid $admin -SystemSid $system -ServiceSid $current -ServiceRights 'FullControl'; " +
                $"(New-Object IO.DirectoryInfo('{escapedPath}')).GetAccessControl().AreAccessRulesProtected"
            );

            Assert.Equal("True", output);
        }
        finally
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
    }

    [Fact]
    public void BootstrapDirectoryCreation_AppliesProtectedAcl()
    {
        var path = Path.Combine(Path.GetTempPath(), $"o365audit-bootstrap-acl-{Guid.NewGuid():N}");
        var escapedPath = path.Replace("'", "''", StringComparison.Ordinal);
        try
        {
            var output = InvokePowerShellFunctions(
                "scripts\\Install-O365AuditTool.ps1",
                $"Initialize-PrivateDirectory -Path '{escapedPath}'; " +
                $"(New-Object IO.DirectoryInfo('{escapedPath}')).GetAccessControl().AreAccessRulesProtected"
            );

            Assert.Equal("True", output);
        }
        finally
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
    }

    private static string InvokeCollectorFunctions(string command)
    {
        return InvokePowerShellFunctions("scripts\\collector.ps1", command);
    }

    private static string InvokePowerShellFunctions(string relativePath, string command)
    {
        var scriptPath = FindRepositoryFile(relativePath);
        var escapedPath = scriptPath.Replace("'", "''", StringComparison.Ordinal);
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \". '{escapedPath}' -FunctionsOnly; {command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("PowerShell could not be started.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        Assert.True(process.ExitCode == 0, $"PowerShell exited with {process.ExitCode}: {stderr}");
        return stdout.Trim();
    }

    private static string FindRepositoryFile(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"{relativePath} was not found from the test output directory.");
    }
}
