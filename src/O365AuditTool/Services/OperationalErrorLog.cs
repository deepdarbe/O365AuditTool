using Microsoft.Data.Sqlite;
using System.Text.Json;

namespace O365AuditTool.Services;

public interface IOperationalErrorLog
{
    void Write(string traceIdentifier, string requestMethod, string requestPath, Exception exception);
}

public sealed class OperationalErrorLog : IOperationalErrorLog
{
    private static readonly object FileGate = new();
    private readonly string _logDirectory;
    private readonly ILogger<OperationalErrorLog> _logger;

    public OperationalErrorLog(
        IConfiguration configuration,
        IWebHostEnvironment environment,
        ILogger<OperationalErrorLog> logger)
    {
        _logger = logger;
        var configuredLogDirectory = configuration["Diagnostics:LogDirectory"];
        if (!string.IsNullOrWhiteSpace(configuredLogDirectory))
        {
            _logDirectory = Path.IsPathRooted(configuredLogDirectory)
                ? configuredLogDirectory
                : Path.GetFullPath(configuredLogDirectory, environment.ContentRootPath);
            return;
        }

        var configured = configuration.GetConnectionString("AuditDb") ?? "Data Source=./data/audit.db";
        var sqlite = new SqliteConnectionStringBuilder(configured);
        var databasePath = sqlite.DataSource;
        if (!Path.IsPathRooted(databasePath))
        {
            databasePath = Path.GetFullPath(databasePath, environment.ContentRootPath);
        }

        var dataDirectory = Path.GetDirectoryName(databasePath)
            ?? Path.Combine(environment.ContentRootPath, "data");
        _logDirectory = Path.Combine(dataDirectory, "logs");
    }

    public void Write(
        string traceIdentifier,
        string requestMethod,
        string requestPath,
        Exception exception)
    {
        try
        {
            Directory.CreateDirectory(_logDirectory);
            var record = new
            {
                timestampUtc = DateTime.UtcNow,
                traceIdentifier,
                requestMethod,
                requestPath,
                exceptionType = exception.GetType().FullName,
                exceptionMessage = exception.Message,
                exceptionChain = BuildExceptionChain(exception),
                stackTrace = exception.ToString()
            };
            var line = JsonSerializer.Serialize(record) + Environment.NewLine;
            var path = Path.Combine(_logDirectory, $"server-errors-{DateTime.UtcNow:yyyyMMdd}.jsonl");
            lock (FileGate)
            {
                File.AppendAllText(path, line);
            }
        }
        catch (Exception logException) when (logException is not OutOfMemoryException and not AccessViolationException)
        {
            _logger.LogWarning(
                logException,
                "Operational error log could not be written for trace {TraceIdentifier}",
                traceIdentifier);
        }
    }

    private static string BuildExceptionChain(Exception exception)
    {
        var parts = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException!)
        {
            parts.Add($"{current.GetType().Name}: {current.Message}");
        }
        return string.Join(" --> ", parts);
    }
}
