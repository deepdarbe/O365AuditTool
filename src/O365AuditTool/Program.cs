using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Services;
using System.Net;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService();

var dashboardPort = builder.Configuration.GetValue<int?>("Server:HttpsPort") ?? 5080;
var healthPort = builder.Configuration.GetValue<int?>("Server:HealthPort") ?? 5081;
var allowInsecureDashboard = builder.Configuration.GetValue<bool>("Server:AllowInsecureHttp");
var certificateThumbprint = builder.Configuration["Server:TlsCertificateThumbprint"];

if (builder.Environment.IsProduction())
{
    if (dashboardPort == healthPort)
    {
        throw new InvalidOperationException("Server:HttpsPort and Server:HealthPort must be different.");
    }

    builder.WebHost.ConfigureKestrel(options =>
    {
        if (allowInsecureDashboard)
        {
            options.ListenAnyIP(dashboardPort);
        }
        else
        {
            var certificate = LoadServerCertificate(certificateThumbprint);
            options.ListenAnyIP(dashboardPort, listen => listen.UseHttps(certificate));
        }

        // The unauthenticated health endpoint is available only on loopback.
        options.Listen(IPAddress.Loopback, healthPort);
    });
}

builder.Services.Configure<CollectorOptions>(builder.Configuration.GetSection("Collector"));
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection("Auth"));
builder.Services.Configure<CopyOptions>(builder.Configuration.GetSection("Copy"));
builder.Services.Configure<RetentionOptions>(builder.Configuration.GetSection("Retention"));

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
builder.Services.AddHostedService<DataRetentionService>();

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-O365Audit-CSRF";
    options.Cookie.Name = builder.Environment.IsProduction() && !allowInsecureDashboard
        ? "__Host-O365Audit-CSRF"
        : "O365Audit-CSRF";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsProduction() && !allowInsecureDashboard
        ? CookieSecurePolicy.Always
        : CookieSecurePolicy.SameAsRequest;
});
builder.Services.AddControllers(options =>
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
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

if (app.Environment.IsProduction() && !allowInsecureDashboard)
{
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    if (app.Environment.IsProduction())
    {
        var isHealthRequest = string.Equals(
            context.Request.Path.Value,
            "/health",
            StringComparison.OrdinalIgnoreCase);
        var isHealthPort = context.Connection.LocalPort == healthPort;
        if (isHealthRequest != isHealthPort)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
    }

    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    if (context.Request.Path.Equals("/") || context.Request.Path.Equals("/index.html"))
    {
        var authorization = context.RequestServices.GetRequiredService<IAuthorizationService>();
        var result = await authorization.AuthorizeAsync(context.User, resource: null, "AuditReader");
        if (!result.Succeeded)
        {
            if (context.User.Identity?.IsAuthenticated == true)
            {
                await context.ForbidAsync();
            }
            else
            {
                await context.ChallengeAsync();
            }
            return;
        }
    }

    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapControllers();
app.MapGet("/api/security/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
    {
        var tokens = antiforgery.GetAndStoreTokens(context);
        return Results.Ok(new { token = tokens.RequestToken });
    })
    .RequireAuthorization("AuditReader");
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

static X509Certificate2 LoadServerCertificate(string? configuredThumbprint)
{
    var thumbprint = configuredThumbprint?
        .Replace(" ", string.Empty, StringComparison.Ordinal)
        .ToUpperInvariant();
    if (string.IsNullOrWhiteSpace(thumbprint))
    {
        throw new InvalidOperationException(
            "Production dashboard TLS is mandatory. Configure Server:TlsCertificateThumbprint or explicitly set Server:AllowInsecureHttp=true for an isolated exception.");
    }

    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);
    var certificate = store.Certificates
        .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: true)
        .OfType<X509Certificate2>()
        .SingleOrDefault(x => x.HasPrivateKey);

    return certificate ?? throw new InvalidOperationException(
        $"A valid LocalMachine/My TLS certificate with private key was not found for thumbprint '{thumbprint}'.");
}
