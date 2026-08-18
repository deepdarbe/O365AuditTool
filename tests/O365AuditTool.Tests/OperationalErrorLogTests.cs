using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using O365AuditTool.Services;
using System.Text.Json;
using Xunit;

namespace O365AuditTool.Tests;

public sealed class OperationalErrorLogTests
{
    [Fact]
    public void Write_PersistsTraceAndExceptionChainAsJsonLine()
    {
        var root = Path.Combine(Path.GetTempPath(), $"o365audit-error-log-{Guid.NewGuid():N}");
        var logDirectory = Path.Combine(root, "logs");
        Directory.CreateDirectory(root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Diagnostics:LogDirectory"] = logDirectory
                })
                .Build();
            var environment = new TestWebHostEnvironment { ContentRootPath = root };
            var log = new OperationalErrorLog(
                configuration,
                environment,
                NullLogger<OperationalErrorLog>.Instance);

            log.Write(
                "TRACE-123",
                "GET",
                "/api/inventory/devices",
                new InvalidOperationException("outer", new IOException("inner")));

            var path = Assert.Single(Directory.GetFiles(logDirectory, "server-errors-*.jsonl"));
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var record = document.RootElement;
            Assert.Equal("TRACE-123", record.GetProperty("traceIdentifier").GetString());
            Assert.Equal("/api/inventory/devices", record.GetProperty("requestPath").GetString());
            Assert.Contains("IOException: inner", record.GetProperty("exceptionChain").GetString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "O365AuditTool.Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string WebRootPath { get; set; } = string.Empty;
        public string EnvironmentName { get; set; } = "Development";
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
