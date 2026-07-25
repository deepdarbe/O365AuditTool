using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService();

builder.Services.Configure<CollectorOptions>(builder.Configuration.GetSection("Collector"));
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection("Auth"));
builder.Services.Configure<CopyOptions>(builder.Configuration.GetSection("Copy"));

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();

builder.Services.AddAuditAuthorization();

builder.Services.AddDbContext<AuditDbContext>(options =>
{
    var configured = builder.Configuration.GetConnectionString("AuditDb") ?? "Data Source=./data/audit.db";
    var resolved = ResolveSqliteConnectionString(configured, builder.Environment.ContentRootPath);
    options.UseSqlite(resolved);
});

builder.Services.AddScoped<IDeviceTargetProvider, ActiveDirectoryTargetProvider>();
builder.Services.AddScoped<IRemoteCollectorRunner, PsExecCollectorRunner>();
builder.Services.AddScoped<IInventoryIngestionService, InventoryIngestionService>();
builder.Services.AddScoped<IInventoryQueryService, InventoryQueryService>();
builder.Services.AddScoped<IScanJobCoordinator, ScanJobCoordinator>();
builder.Services.AddScoped<IArtifactCopyPlanService, ArtifactCopyPlanService>();
builder.Services.AddHostedService<ScanOrchestratorService>();
builder.Services.AddHostedService<ArtifactCopyService>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

var dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
Directory.CreateDirectory(dataDir);
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
    db.Database.EnsureCreated();
    DatabaseSchemaBootstrapper.EnsureCurrentSchema(db);
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapControllers();
app.MapGet("/health", async (AuditDbContext db, CancellationToken cancellationToken) =>
    await db.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "healthy" })
        : Results.StatusCode(StatusCodes.Status503ServiceUnavailable))
    .AllowAnonymous();

app.Run();

static string ResolveSqliteConnectionString(string connectionString, string contentRoot)
{
    const string key = "Data Source=";
    var idx = connectionString.IndexOf(key, StringComparison.OrdinalIgnoreCase);
    if (idx < 0)
    {
        return connectionString;
    }

    var pathStart = idx + key.Length;
    var rest = connectionString[pathStart..];
    var semicolon = rest.IndexOf(';');
    var pathPart = semicolon >= 0 ? rest[..semicolon] : rest;
    var trimmedPath = pathPart.Trim().Trim('"');

    if (string.IsNullOrWhiteSpace(trimmedPath) || Path.IsPathRooted(trimmedPath))
    {
        return connectionString;
    }

    var normalized = trimmedPath
        .Replace("./", string.Empty, StringComparison.Ordinal)
        .Replace(".\\", string.Empty, StringComparison.Ordinal);

    var absolute = Path.Combine(contentRoot, normalized);
    return connectionString.Replace(pathPart, absolute, StringComparison.Ordinal);
}
