using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Services;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// Make OEM/ANSI code pages (e.g. CP857/CP1254 on Turkish Windows) available so the
// collector can decode PsExec's localized console output correctly. Without this the
// default .NET set is UTF-8/ASCII/Latin1 only and localized error markers are mangled.
System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

// A startup failure used to leave nothing an operator could read: under the Service Control
// Manager there is no console, and the Event Log provider drops every record silently when its
// source has not been registered. Measured on BURCUDC, where the service refused to start and the
// deploy rollback moved the app directory aside, so neither the documented console run nor the
// diagnostics script could reach the real exception.
string? startupLogDirectory = null;
try
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseWindowsService();

    startupLogDirectory = StartupDiagnostics.ResolveLogDirectory(
        builder.Configuration,
        builder.Environment.ContentRootPath);

    // Second sink for Warning and above. The hosted services report only through ILogger, and the
    // Event Log provider added by UseWindowsService disables itself for the whole process the
    // first time its source is missing, so without this file the operator sees nothing.
    var diagnosticFileLoggerProvider = new RollingFileLoggerProvider(startupLogDirectory);
    builder.Logging.AddProvider(diagnosticFileLoggerProvider);

    // Kestrel resolves its options during host start, before any request-scoped logger exists, so
    // certificate decisions are reported through a factory built by hand over the same sinks.
    using var startupLoggerFactory = LoggerFactory.Create(logging =>
    {
        logging.AddConsole();
        logging.AddProvider(diagnosticFileLoggerProvider);
    });
    var startupLogger = startupLoggerFactory.CreateLogger("O365AuditTool.Startup");

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
                var certificate = LoadServerCertificate(certificateThumbprint, startupLogger);
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
    builder.Services.AddSingleton<IActiveDirectoryStructureProvider, ActiveDirectoryStructureProvider>();
    builder.Services.AddScoped<IRemoteCollectorRunner, PsExecCollectorRunner>();
    builder.Services.AddScoped<IInventoryIngestionService, InventoryIngestionService>();
    builder.Services.AddScoped<IInventoryQueryService, InventoryQueryService>();
    builder.Services.AddScoped<IScanJobCoordinator, ScanJobCoordinator>();
    builder.Services.AddScoped<IArtifactCopyPlanService, ArtifactCopyPlanService>();
    builder.Services.AddSingleton<IOperationalErrorLog, OperationalErrorLog>();
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
    builder.Services.AddControllersWithViews(options =>
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
        DatabaseSchemaBootstrapper.ValidateCurrentSchema(db);
        DatabaseSchemaBootstrapper.ConfigureConcurrentAccess(db);
    }

    app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
    {
        var feature = context.Features.Get<IExceptionHandlerFeature>();
        var exception = feature?.Error ?? new InvalidOperationException("Unhandled request failure.");
        var logger = context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("O365AuditTool.UnhandledRequest");
        logger.LogError(exception, "Unhandled request failure {TraceIdentifier}", context.TraceIdentifier);
        context.RequestServices.GetRequiredService<IOperationalErrorLog>().Write(
            context.TraceIdentifier,
            context.Request.Method,
            context.Request.Path.Value ?? string.Empty,
            exception);
        context.Response.Headers["X-O365Audit-TraceId"] = context.TraceIdentifier;

        var sqliteException = FindSqliteException(exception);
        var databaseBusy = sqliteException?.SqliteErrorCode is 5 or 6;
        if (databaseBusy)
        {
            context.Response.Headers.RetryAfter = "2";
        }

        await Results.Problem(
            statusCode: databaseBusy
                ? StatusCodes.Status503ServiceUnavailable
                : StatusCodes.Status500InternalServerError,
            title: databaseBusy
                ? "Envanter veritabanı geçici olarak meşgul"
                : "Sunucu isteği tamamlayamadı",
            detail: $"İzleme kodu: {context.TraceIdentifier}")
            .ExecuteAsync(context);
    }));

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
    app.MapGet("/api/security/session", async (HttpContext context, IAuthorizationService authorization) =>
    {
        var roles = new List<string>();
        foreach (var role in new[] { "AuditReader", "MigrationPlanner", "AuditAdmin" })
        {
            if ((await authorization.AuthorizeAsync(context.User, role)).Succeeded)
            {
                roles.Add(role);
            }
        }

        return Results.Ok(new
        {
            userName = context.User.Identity?.Name,
            authenticationType = context.User.Identity?.AuthenticationType,
            isAuthenticated = context.User.Identity?.IsAuthenticated == true,
            roles,
            appVersion = AppVersion.Current
        });
    })
        .RequireAuthorization("AuditReader");
    app.MapGet("/health", async (AuditDbContext db, CancellationToken cancellationToken) =>
    {
        if (!await db.Database.CanConnectAsync(cancellationToken))
        {
            return Results.Json(new { status = "unhealthy", reason = "database connection failed" }, statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        var schemaFailures = DatabaseSchemaBootstrapper.GetSchemaFailures(db);
        return schemaFailures.Count == 0
            ? Results.Ok(new { status = "healthy" })
            : Results.Json(new { status = "unhealthy", reason = "database schema validation failed" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    })
        .AllowAnonymous();

    app.Run();
}
catch (Exception startupException)
{
    StartupDiagnostics.RecordStartupFailure(startupLogDirectory, startupException);
    throw;
}

static string ResolveSqliteConnectionString(string connectionString, string contentRoot)
{
    var sqlite = new SqliteConnectionStringBuilder(connectionString);
    if (!string.IsNullOrWhiteSpace(sqlite.DataSource) && !Path.IsPathRooted(sqlite.DataSource))
    {
        var normalized = sqlite.DataSource
            .Replace("./", string.Empty, StringComparison.Ordinal)
            .Replace(".\\", string.Empty, StringComparison.Ordinal);
        sqlite.DataSource = Path.Combine(contentRoot, normalized);
    }

    sqlite.DefaultTimeout = Math.Max(sqlite.DefaultTimeout, 30);
    sqlite.Pooling = true;
    return sqlite.ToString();
}

static SqliteException? FindSqliteException(Exception exception)
{
    for (var current = exception; current is not null; current = current.InnerException!)
    {
        if (current is SqliteException sqliteException)
        {
            return sqliteException;
        }
    }

    return null;
}

static X509Certificate2 LoadServerCertificate(string? configuredThumbprint, ILogger logger)
{
    const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

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

    // validOnly:false because that flag also demands a trusted chain, which an internal
    // self-signed certificate can never satisfy. Measured on BURCUDC: the configured certificate
    // was present with its private key and only its untrusted root made the store hide it, so the
    // service could not start and the message named no cause. The checks below are explicit
    // instead, and each rejection states which one failed.
    var candidates = store.Certificates
        .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
        .OfType<X509Certificate2>()
        .ToList();

    if (candidates.Count == 0)
    {
        throw new InvalidOperationException(
            $"TLS certificate '{thumbprint}' is not present in LocalMachine\\My. Import the certificate together with its private key into the machine personal store.");
    }

    var withPrivateKey = candidates.Where(x => x.HasPrivateKey).ToList();
    if (withPrivateKey.Count == 0)
    {
        throw new InvalidOperationException(
            $"TLS certificate '{thumbprint}' is present in LocalMachine\\My but has no usable private key. Re-import it from a PFX and grant the service identity read access to the key.");
    }

    // NotBefore/NotAfter are exposed in local time, so the comparison has to use local time too.
    var now = DateTime.Now;
    var currentlyValid = withPrivateKey
        .Where(x => now >= x.NotBefore && now <= x.NotAfter)
        .ToList();
    if (currentlyValid.Count == 0)
    {
        var latest = withPrivateKey.OrderByDescending(x => x.NotAfter).First();
        throw new InvalidOperationException(
            $"TLS certificate '{thumbprint}' is outside its validity window (NotBefore {latest.NotBefore:yyyy-MM-dd HH:mm:ss}, NotAfter {latest.NotAfter:yyyy-MM-dd HH:mm:ss}, now {now:yyyy-MM-dd HH:mm:ss}). Renew or replace it.");
    }

    var serverAuthentication = currentlyValid.Where(HasServerAuthenticationUsage).ToList();
    if (serverAuthentication.Count == 0)
    {
        throw new InvalidOperationException(
            $"TLS certificate '{thumbprint}' does not permit Server Authentication (EKU {ServerAuthenticationOid}). Re-issue it from a template that includes server authentication.");
    }

    // A store can hold the same thumbprint more than once (a re-import binds a second key
    // container). Pick deterministically instead of letting SingleOrDefault throw at startup.
    var certificate = serverAuthentication
        .OrderByDescending(x => x.NotAfter)
        .ThenByDescending(x => x.NotBefore)
        .ThenBy(x => x.Subject, StringComparer.Ordinal)
        .First();

    WarnOnUnvalidatedChain(certificate, thumbprint, logger);
    return certificate;

    static bool HasServerAuthenticationUsage(X509Certificate2 certificate)
    {
        var enhancedKeyUsages = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .ToList();

        // An absent EKU extension means "any purpose" (RFC 5280 4.2.1.12), which is how the
        // hand-made self-signed certificates used on internal deployments look.
        return enhancedKeyUsages.Count == 0
            || enhancedKeyUsages.Any(extension => extension.EnhancedKeyUsages
                .OfType<Oid>()
                .Any(oid => string.Equals(oid.Value, ServerAuthenticationOid, StringComparison.Ordinal)));
    }

    static void WarnOnUnvalidatedChain(X509Certificate2 certificate, string thumbprint, ILogger logger)
    {
        string chainStatus;
        try
        {
            using var chain = new X509Chain();
            // A domain controller without outbound internet would otherwise stall on CRL retrieval.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (chain.Build(certificate))
            {
                return;
            }

            chainStatus = chain.ChainStatus.Length == 0
                ? "unspecified"
                : string.Join(", ", chain.ChainStatus.Select(x => $"{x.Status}: {x.StatusInformation?.Trim()}"));
        }
        catch (Exception ex)
        {
            // This is the only purely diagnostic step on the startup path, and it runs after the
            // certificate has already been accepted. Chain building can throw (CryptoAPI, a broken
            // store, a revoked provider); a diagnostic must never be the reason the service refuses
            // to start.
            logger.LogWarning(
                ex,
                "TLS certificate {Thumbprint} chain could not be evaluated. The certificate itself was accepted.",
                thumbprint);
            return;
        }

        // Accepted on purpose: an internal deployment may legitimately serve a self-signed
        // certificate. The operator still has to see it, because every client will warn.
        logger.LogWarning(
            "TLS certificate {Thumbprint} ({Subject}, issuer {Issuer}) was accepted although its chain does not validate: {ChainStatus}. Clients will not trust it until the issuer is installed in their trusted roots.",
            thumbprint,
            certificate.Subject,
            certificate.Issuer,
            chainStatus);
    }
}

/// <summary>
/// Startup-time diagnostics that must work before the DI container exists and after the host has
/// failed to start, i.e. exactly when no other sink in this application is reachable.
/// </summary>
file static class StartupDiagnostics
{
    private const string EventLogSourceName = "O365AuditTool";

    // The Windows Event Log refuses entries longer than 31839 characters and loses the record
    // entirely instead of truncating it, so a long stack trace has to be cut here.
    private const int MaxEventLogMessageLength = 30000;

    public static string ResolveLogDirectory(IConfiguration configuration, string contentRootPath)
    {
        var configured = configuration["Diagnostics:LogDirectory"];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.IsPathRooted(configured)
                ? configured
                : Path.GetFullPath(configured, contentRootPath);
        }

        // Same derivation as OperationalErrorLog, so every local sink lands in one directory the
        // operator can be pointed at.
        var sqlite = new SqliteConnectionStringBuilder(
            configuration.GetConnectionString("AuditDb") ?? "Data Source=./data/audit.db");
        if (string.IsNullOrWhiteSpace(sqlite.DataSource))
        {
            return Path.Combine(contentRootPath, "data", "logs");
        }

        var databasePath = Path.IsPathRooted(sqlite.DataSource)
            ? sqlite.DataSource
            : Path.GetFullPath(sqlite.DataSource, contentRootPath);
        var dataDirectory = Path.GetDirectoryName(databasePath)
            ?? Path.Combine(contentRootPath, "data");
        return Path.Combine(dataDirectory, "logs");
    }

    public static void RecordStartupFailure(string? logDirectory, Exception exception)
    {
        // Best effort throughout: the caller rethrows, so a failing sink must never replace the
        // original startup exception with a logging exception.
        try
        {
            var timestampUtc = DateTime.UtcNow;
            var report = BuildReport(timestampUtc, exception);
            var fileName = $"startup-failure-{timestampUtc.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture)}Z.log";

            if (!TryWriteReport(logDirectory, fileName, report))
            {
                TryWriteReport(AppContext.BaseDirectory, fileName, report);
            }

            TryWriteEventLog(report);
        }
        catch (Exception recordException) when (recordException is not OutOfMemoryException and not AccessViolationException)
        {
        }
    }

    private static string BuildReport(DateTime timestampUtc, Exception exception)
    {
        var report = new System.Text.StringBuilder();
        report.AppendLine(
            $"O365AuditTool startup failure at {timestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}Z");
        report.AppendLine($"Version      : {AppVersion.Current}");
        report.AppendLine($"Machine      : {Environment.MachineName}");
        report.AppendLine($"Identity     : {Environment.UserDomainName}\\{Environment.UserName}");
        report.AppendLine($"Environment  : {Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")}");
        report.AppendLine($"BaseDirectory: {AppContext.BaseDirectory}");
        report.AppendLine();

        for (var current = exception; current is not null; current = current.InnerException)
        {
            report.AppendLine($"{current.GetType().FullName}: {current.Message}");
        }

        report.AppendLine();
        report.AppendLine(exception.ToString());
        return report.ToString();
    }

    private static bool TryWriteReport(string? directory, string fileName, string report)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, fileName), report);
            return true;
        }
        catch (Exception writeException) when (writeException is not OutOfMemoryException and not AccessViolationException)
        {
            return false;
        }
    }

    private static void TryWriteEventLog(string report)
    {
        try
        {
            // SourceExists throws for a non-elevated identity when the source is missing, and
            // creating one needs administrative rights, so both stay inside this guard: the file
            // written above is the channel that always works.
            if (!System.Diagnostics.EventLog.SourceExists(EventLogSourceName))
            {
                System.Diagnostics.EventLog.CreateEventSource(EventLogSourceName, "Application");
            }

            var message = report.Length > MaxEventLogMessageLength
                ? report[..MaxEventLogMessageLength]
                : report;
            System.Diagnostics.EventLog.WriteEntry(
                EventLogSourceName,
                message,
                System.Diagnostics.EventLogEntryType.Error);
        }
        catch (Exception eventLogException) when (eventLogException is not OutOfMemoryException and not AccessViolationException)
        {
        }
    }
}

/// <summary>
/// Warning-and-above file sink for the hosted services. They report only through ILogger, and the
/// Event Log provider added by UseWindowsService disables itself for the rest of the process the
/// first time it cannot reach its source, which on a fresh non-admin install is the first write.
/// </summary>
file sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private const long MaxFileBytes = 8L * 1024 * 1024;
    private const int MaxRollIndex = 99;

    // Static so that two provider instances over the same directory still serialize their writes.
    private static readonly object FileGate = new();

    private readonly string _logDirectory;
    private string? _currentStamp;
    private string? _currentPath;

    public RollingFileLoggerProvider(string logDirectory)
    {
        _logDirectory = logDirectory;
    }

    public ILogger CreateLogger(string categoryName) => new RollingFileLogger(this, categoryName);

    public void Dispose()
    {
        // Nothing to release: every append opens and closes the file inside the lock. This stays a
        // no-op on purpose, because the startup logger factory and the host logger factory share
        // one instance and whichever is disposed first must not silence the other.
    }

    private void Append(string categoryName, LogLevel logLevel, EventId eventId, string message, Exception? exception)
    {
        try
        {
            var line = new System.Text.StringBuilder()
                .Append(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture))
                .Append("Z [")
                .Append(ResolveLevelTag(logLevel))
                .Append("] ")
                .Append(categoryName)
                .Append('[')
                .Append(eventId.Id.ToString(CultureInfo.InvariantCulture))
                .Append("] ")
                .AppendLine(message);
            if (exception is not null)
            {
                line.AppendLine(exception.ToString());
            }

            lock (FileGate)
            {
                Directory.CreateDirectory(_logDirectory);
                File.AppendAllText(ResolveCurrentPath(), line.ToString());
            }
        }
        catch (Exception writeException) when (writeException is not OutOfMemoryException and not AccessViolationException)
        {
            // A diagnostics sink that throws would take down the very service it documents.
        }
    }

    private string ResolveCurrentPath()
    {
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        if (_currentPath is not null
            && string.Equals(_currentStamp, stamp, StringComparison.Ordinal)
            && !ExceedsSizeCap(_currentPath))
        {
            return _currentPath;
        }

        var path = Path.Combine(_logDirectory, $"service-{stamp}.log");
        for (var index = 1; index <= MaxRollIndex && ExceedsSizeCap(path); index++)
        {
            path = Path.Combine(
                _logDirectory,
                $"service-{stamp}-{index.ToString("D2", CultureInfo.InvariantCulture)}.log");
        }

        _currentStamp = stamp;
        _currentPath = path;
        return path;
    }

    private static bool ExceedsSizeCap(string path)
    {
        var file = new FileInfo(path);
        return file.Exists && file.Length >= MaxFileBytes;
    }

    private static string ResolveLevelTag(LogLevel logLevel) => logLevel switch
    {
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => logLevel.ToString().ToUpperInvariant()
    };

    private sealed class RollingFileLogger : ILogger
    {
        private readonly RollingFileLoggerProvider _provider;
        private readonly string _categoryName;

        public RollingFileLogger(RollingFileLoggerProvider provider, string categoryName)
        {
            _provider = provider;
            _categoryName = categoryName;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            // The logging pipeline filters by configuration, not by this provider, so the level
            // gate has to be re-applied here before the message is formatted.
            if (!IsEnabled(logLevel) || formatter is null)
            {
                return;
            }

            _provider.Append(_categoryName, logLevel, eventId, formatter(state, exception), exception);
        }
    }
}
