using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace O365AuditTool.Tests;

/// <summary>
/// A disposable stand-in for psexec.exe used to exercise PsExecCollectorRunner's process path.
/// The runner starts the configured binary directly with UseShellExecute=false, which cannot
/// launch a .cmd/.bat, so only a real executable works. The stub is compiled once per test run
/// with the in-box .NET Framework compiler: it ships with every supported Windows, needs no
/// NuGet restore, and never builds the solution under test. Each instance gets its own copy so
/// the sidecar files (config, recorded arguments, recorded process ids) cannot collide when
/// xUnit runs test classes in parallel.
/// </summary>
internal sealed class PsExecStubExecutable : IDisposable
{
    private const string StubSourceRelativePath = @"TestStubs\PsExecStubProgram.cs.txt";
    private static readonly Lazy<string> CompiledStub = new(Compile);

    private readonly string _directory;

    private PsExecStubExecutable(string directory, string executablePath, string sha256)
    {
        _directory = directory;
        ExecutablePath = executablePath;
        Sha256 = sha256;
    }

    public string ExecutablePath { get; }

    /// <summary>Hash of this copy: the runner refuses to start a binary it cannot verify.</summary>
    public string Sha256 { get; }

    /// <summary>True once the stub actually ran, which is how a test proves PsExec was skipped.</summary>
    public bool WasStarted => File.Exists(ArgumentPath);

    /// <summary>The argument list the runner passed, in order.</summary>
    public string[] Arguments => WasStarted ? File.ReadAllLines(ArgumentPath) : [];

    /// <summary>Process ids a hanging stub recorded: its own first, then its child's.</summary>
    public int[] ProcessTree => File.Exists(ProcessIdPath)
        ? File.ReadAllLines(ProcessIdPath).Select(line => int.Parse(line, CultureInfo.InvariantCulture)).ToArray()
        : [];

    private string ArgumentPath => ExecutablePath + ".args";

    private string ProcessIdPath => ExecutablePath + ".pids";

    /// <summary>A stub that writes the given streams and exits with <paramref name="exitCode"/>.</summary>
    public static PsExecStubExecutable Exiting(int exitCode, string standardOutput = "", string standardError = "") =>
        Create([
            "exit=" + exitCode.ToString(CultureInfo.InvariantCulture),
            "stdout=" + Encode(standardOutput),
            "stderr=" + Encode(standardError)
        ]);

    /// <summary>A stub that never exits and spawns a child, so a timeout must kill a real tree.</summary>
    public static PsExecStubExecutable Hanging() => Create(["hang=1"]);

    public void Dispose()
    {
        // A tree kill that failed would otherwise leave the stub sleeping and hold the
        // directory open; assertions have already run by the time Dispose is reached.
        foreach (var processId in ProcessTree)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // The expected case: the runner already killed it.
            }
        }

        TryDelete(_directory);
    }

    private static PsExecStubExecutable Create(string[] configuration)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"o365audit-psexec-stub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);

        var executablePath = Path.Combine(directory, "psexec.exe");
        File.Copy(CompiledStub.Value, executablePath);
        // ".stub", never "<exe>.config": Windows parses a sibling application configuration file
        // while it builds the activation context, and a non-XML one made CreateProcess fail with
        // "side-by-side configuration is incorrect" before PsExecCollectorRunner ran at all.
        File.WriteAllLines(executablePath + ".stub", configuration);

        using var stream = File.OpenRead(executablePath);
        return new PsExecStubExecutable(directory, executablePath, Convert.ToHexString(SHA256.HashData(stream)));
    }

    private static string Encode(string text)
    {
        // The runner decodes PsExec's streams with the host OEM console code page (CP857 on a
        // Turkish server, CP437 elsewhere), so only ASCII reaches the assertions unchanged on
        // every machine the suite runs on.
        if (text.Any(character => character > 127))
        {
            throw new ArgumentException("Stub stream content must be ASCII to survive the OEM console code page.", nameof(text));
        }

        return Convert.ToBase64String(Encoding.ASCII.GetBytes(text));
    }

    private static string Compile()
    {
        var compiler = ResolveFrameworkCompiler();
        var source = Path.Combine(AppContext.BaseDirectory, StubSourceRelativePath);
        if (!File.Exists(source))
        {
            throw new FileNotFoundException("The PsExec stub source was not copied to the test output directory.", source);
        }

        var directory = Path.Combine(Path.GetTempPath(), $"o365audit-psexec-stub-build-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        AppDomain.CurrentDomain.ProcessExit += (_, _) => TryDelete(directory);

        var target = Path.Combine(directory, "psexec-stub.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = compiler,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-nologo");
        startInfo.ArgumentList.Add("-optimize+");
        startInfo.ArgumentList.Add("-target:exe");
        startInfo.ArgumentList.Add("-out:" + target);
        startInfo.ArgumentList.Add(source);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The C# compiler could not be started.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0 || !File.Exists(target))
        {
            throw new InvalidOperationException(
                $"The PsExec stub could not be compiled (exit {process.ExitCode}): {stderr}{stdout}");
        }

        return target;
    }

    private static string ResolveFrameworkCompiler()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string[] candidates =
        [
            Path.Combine(windows, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
            Path.Combine(windows, "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe")
        ];

        return candidates.FirstOrDefault(File.Exists)
            ?? throw new InvalidOperationException(
                "The in-box .NET Framework C# compiler was not found, so the PsExec stub cannot be built.");
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception)
        {
            // Temporary files must never fail a test run.
        }
    }
}
