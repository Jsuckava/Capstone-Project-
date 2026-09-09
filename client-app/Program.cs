using Serilog;
using BlockGo.Services;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;
using Client_app.Services;
using Client_app.Middleware;
using Client_app.Models;
using Client_app.Controllers;
using For_Testing_Only_Capstone.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Client_app.Microservices;

AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .WriteTo.File(
        "logs/app-.txt",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .Enrich.FromLogContext()
    .CreateLogger();

try
{
    Log.Information("Application starting up...");
    
    string[] envPaths = { 
        Path.Combine(Directory.GetCurrentDirectory(), ".env"),
        Path.Combine(Directory.GetCurrentDirectory(), "..", "network", ".env"),
        Path.Combine(Directory.GetCurrentDirectory(), "..", "middleware", ".env")
    };

    foreach (var envPath in envPaths)
    {
        if (File.Exists(envPath))
        {
            foreach (var line in File.ReadAllLines(envPath))
            {
                var trimmedLine = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith("#")) continue;
                if (trimmedLine.StartsWith("export ")) trimmedLine = trimmedLine.Substring(7).Trim();
                
                var parts = trimmedLine.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2)
                {
                    var key = parts[0].Trim();
                    var value = parts[1].Split('#')[0].Trim().Trim('"', '\'');
                    
                    if (value.Contains("prefer-standby", StringComparison.OrdinalIgnoreCase)) 
                        value = System.Text.RegularExpressions.Regex.Replace(value, @"(?i)prefer-standby", "PreferStandby");
                    value = System.Text.RegularExpressions.Regex.Replace(value, @"(?i)target[\s_]*session[\s_]*attributes\s*=\s*[^;]+;?", "");
                    
                    if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)))
                    {
                        Environment.SetEnvironmentVariable(key, value);
                    }
                }
            }
        }
    }

    foreach (System.Collections.DictionaryEntry env in Environment.GetEnvironmentVariables())
    {
        var key = env.Key?.ToString();
        var value = env.Value?.ToString();
        if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value))
        {
            bool mutated = false;
            if (value.IndexOf("prefer-standby", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                value = System.Text.RegularExpressions.Regex.Replace(value, @"(?i)prefer-standby", "PreferStandby");
                mutated = true;
            }
            if (value.IndexOf("target", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var newVal = System.Text.RegularExpressions.Regex.Replace(value, @"(?i)target[\s_]*session[\s_]*attributes\s*=\s*[^;]+;?", "");
                if (newVal != value) { value = newVal; mutated = true; }
            }
            if (mutated) Environment.SetEnvironmentVariable(key, value);
        }
    }

    Environment.SetEnvironmentVariable("PGTARGETSESSIONATTRS", null);
    Environment.SetEnvironmentVariable("PGTARGETSESSIONATTR", null);

    var builder = WebApplication.CreateBuilder(args);
    var dotnetServiceName = DotnetServiceTopology.ResolveServiceName(builder.Configuration);
    var dotnetServicePort = int.TryParse(
        Environment.GetEnvironmentVariable("DOTNET_SERVICE_PORT"),
        out var configuredServicePort)
        ? configuredServicePort
        : 5000;
    builder.WebHost.UseUrls($"http://0.0.0.0:{dotnetServicePort}");
    builder.Host.UseSerilog();


    var masterConn = builder.Configuration.GetConnectionString("MasterConnection");
    var replicaConn = builder.Configuration.GetConnectionString("ReplicaConnection");
    var postgresConn = builder.Configuration.GetConnectionString("PostgresConnection");
    var stripRegex = new System.Text.RegularExpressions.Regex(@"(?i)target[\s_]*session[\s_]*attributes\s*=\s*[^;]+;?");
    var configOverrides = new Dictionary<string, string?>();
    if (!string.IsNullOrEmpty(masterConn)) configOverrides["ConnectionStrings:MasterConnection"] = stripRegex.Replace(masterConn, "");
    if (!string.IsNullOrEmpty(replicaConn)) configOverrides["ConnectionStrings:ReplicaConnection"] = stripRegex.Replace(replicaConn, "");
    if (!string.IsNullOrEmpty(postgresConn)) configOverrides["ConnectionStrings:PostgresConnection"] = stripRegex.Replace(postgresConn, "");

    var postgresHost = Environment.GetEnvironmentVariable("POSTGRES_HOST");
    var postgresPort = Environment.GetEnvironmentVariable("POSTGRES_PORT") ?? "5432";
    var postgresDatabase = Environment.GetEnvironmentVariable("POSTGRES_DB");
    var postgresUser = Environment.GetEnvironmentVariable("POSTGRES_USER");
    var postgresPassword = Environment.GetEnvironmentVariable("POSTGRES_PASS");
    if (!string.IsNullOrWhiteSpace(postgresHost)
        && !string.IsNullOrWhiteSpace(postgresDatabase)
        && !string.IsNullOrWhiteSpace(postgresUser)
        && !string.IsNullOrWhiteSpace(postgresPassword))
    {
        var generatedConnection = new NpgsqlConnectionStringBuilder
        {
            Host = postgresHost,
            Port = int.TryParse(postgresPort, out var parsedPostgresPort) ? parsedPostgresPort : 5432,
            Database = postgresDatabase,
            Username = postgresUser,
            Password = postgresPassword,
            Pooling = true
        }.ConnectionString;
        configOverrides["ConnectionStrings:MasterConnection"] = generatedConnection;
        configOverrides["ConnectionStrings:ReplicaConnection"] = generatedConnection;
        configOverrides["ConnectionStrings:PostgresConnection"] = generatedConnection;
    }

    var internalApiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY");
    if (!string.IsNullOrEmpty(internalApiKey)) configOverrides["InternalApiKey"] = internalApiKey;
    var ipfsEncryptionKey = Environment.GetEnvironmentVariable("IPFS_ENCRYPTION_KEY");
    if (!string.IsNullOrEmpty(ipfsEncryptionKey)) configOverrides["IpfsEncryptionKey"] = ipfsEncryptionKey;
    var vaultPassword = Environment.GetEnvironmentVariable("VAULT_PASSWORD");
    if (!string.IsNullOrEmpty(vaultPassword)) configOverrides["VaultPassword"] = vaultPassword;

    builder.Configuration.AddInMemoryCollection(configOverrides);

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowFrontend", policy =>
        {
            policy.WithOrigins("http://localhost:8080", "http://localhost:8090", "http://localhost:8100", "http://localhost:3000") 
                  .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                  .WithHeaders("Content-Type", "Authorization", "x-user-identity", "x-api-key")
                  .AllowCredentials();
        });
    });

    if (dotnetServiceName == DotnetServiceTopology.Gateway)
    {
        var gatewayConfiguration = DotnetServiceTopology.BuildGatewayConfiguration(builder.Configuration);
        builder.Services
            .AddReverseProxy()
            .LoadFromMemory(gatewayConfiguration.Routes, gatewayConfiguration.Clusters);
        builder.Services.AddHttpClient("DotnetGatewayReadiness", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(3);
        });
        builder.Services.AddProblemDetails();

        var gatewayApp = builder.Build();
        gatewayApp.UseSerilogRequestLogging();
        gatewayApp.UseCors("AllowFrontend");
        gatewayApp.Use(async (context, next) =>
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            await next();
        });
        gatewayApp.MapGet("/health", () => Results.Ok(new
        {
            status = "healthy",
            service = "dotnet-api-gateway",
            architecture = "microservices"
        }));
        gatewayApp.MapGet("/api/backend/health", () => Results.Ok(new
        {
            status = "healthy",
            service = "dotnet-api-gateway",
            architecture = "microservices"
        }));
        gatewayApp.MapGet("/api/ready", async (IHttpClientFactory httpClientFactory, CancellationToken cancellationToken) =>
        {
            var client = httpClientFactory.CreateClient("DotnetGatewayReadiness");
            var checks = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            var isReady = true;

            foreach (var destination in DotnetServiceTopology.GatewayDestinations(builder.Configuration))
            {
                try
                {
                    using var response = await client.GetAsync($"{destination.Value.TrimEnd('/')}/health", cancellationToken);
                    var healthy = response.IsSuccessStatusCode;
                    checks[destination.Key] = new { ready = healthy, statusCode = (int)response.StatusCode };
                    isReady &= healthy;
                }
                catch (Exception exception)
                {
                    checks[destination.Key] = new { ready = false, error = exception.Message };
                    isReady = false;
                }
            }

            return Results.Json(
                new { status = isReady ? "ready" : "not_ready", services = checks },
                statusCode: isReady ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
        });
        gatewayApp.MapReverseProxy();

        Log.Information("ASP.NET microservice gateway configured for {ServiceCount} internal services", gatewayConfiguration.Clusters.Count);
        gatewayApp.Run();
        return;
    }

    var mvcBuilder = builder.Services.AddControllers();
    var allowedControllers = DotnetServiceTopology.ControllersFor(dotnetServiceName);
    if (allowedControllers is not null)
    {
        mvcBuilder.ConfigureApplicationPartManager(manager =>
            manager.FeatureProviders.Add(new ServiceControllerFeatureProvider(allowedControllers)));
    }
    builder.Services.AddMemoryCache();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    var signalRBuilder = builder.Services.AddSignalR(options =>
    {
        options.MaximumReceiveMessageSize = 8 * 1024 * 1024;
    });

    var redisConnectionString = Environment.GetEnvironmentVariable("REDIS_CONNECTION_STRING")
        ?? builder.Configuration["Redis:ConnectionString"];
    if (!string.IsNullOrWhiteSpace(redisConnectionString))
    {
        signalRBuilder.AddStackExchangeRedis(redisConnectionString);
        Log.Information("SignalR Redis backplane enabled.");
    }
    else
    {
        Log.Warning("SignalR Redis backplane disabled because Redis connection string is not configured.");
    }

    builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
    builder.Services.AddProblemDetails();

    var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? throw new InvalidOperationException("JWT_SECRET environment variable is required.");
    // Keep token validation byte-for-byte compatible with the Node login service.
    var jwtKey = SHA256.HashData(Encoding.UTF8.GetBytes(jwtSecret.Trim()));

    builder.Services.AddAuthorization();
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(jwtKey),
            ValidateIssuer = false,
            ValidateAudience = false,
            NameClaimType = "username",
            RoleClaimType = "dbRole"
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var email = context.Principal?.Identity?.Name
                    ?? context.Principal?.Claims.FirstOrDefault(claim => claim.Type == "email")?.Value;
                var tokenRole = context.Principal?.Claims.FirstOrDefault(claim => claim.Type == "dbRole")?.Value;
                if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(tokenRole))
                {
                    context.Fail("The access token is missing its account identity.");
                    return;
                }

                var validationConnection = builder.Configuration.GetConnectionString("MasterConnection")
                    ?? builder.Configuration.GetConnectionString("PostgresConnection");
                if (string.IsNullOrWhiteSpace(validationConnection))
                {
                    context.Fail("Account validation is unavailable.");
                    return;
                }

                try
                {
                    await using var connection = new NpgsqlConnection(validationConnection);
                    await connection.OpenAsync(context.HttpContext.RequestAborted);
                    await using var command = new NpgsqlCommand(@"
                        SELECT role
                        FROM users
                        WHERE LOWER(email) = LOWER(@email)
                          AND is_active = TRUE
                          AND LOWER(status) = 'approved'
                        LIMIT 1;", connection);
                    command.Parameters.AddWithValue("email", email);
                    var databaseRole = (await command.ExecuteScalarAsync(context.HttpContext.RequestAborted))?.ToString();
                    static string NormalizeRole(string value)
                    {
                        var normalized = value.Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
                        return normalized switch
                        {
                            "systemadmin" or "sysadmin" or "system_administrator" => "system_admin",
                            "deptadmin" or "dept_admin" or "department" or "departmentadmin" or "chairperson" or "department_head" or "admin" => "department_admin",
                            "instructor" => "faculty",
                            var role => role
                        };
                    }
                    if (string.IsNullOrWhiteSpace(databaseRole) || NormalizeRole(databaseRole) != NormalizeRole(tokenRole))
                    {
                        context.Fail("This account is inactive, changed, or no longer authorized.");
                    }
                }
                catch (Exception exception)
                {
                    Log.Warning(exception, "Could not validate active access for {Email}.", email);
                    context.Fail("Account validation failed.");
                }
            },
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && 
                    (path.StartsWithSegments("/chatHub") || path.StartsWithSegments("/api/chatHub") || path.StartsWithSegments("/api/Grades/view-ipfs")))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });

    var rateLimitOptions = builder.Configuration.GetSection("RateLimiting");
    var permitLimit = int.Parse(rateLimitOptions["PermitLimit"] ?? "10");
    var windowSeconds = int.Parse(rateLimitOptions["WindowSeconds"] ?? "60");

    builder.Services.AddRateLimiter(options =>
    {
        options.AddPolicy("fixed", httpContext =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: httpContext.User.Identity?.Name ?? httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
                factory: partition => new FixedWindowRateLimiterOptions
                {
                    AutoReplenishment = true,
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromSeconds(windowSeconds)
                }));
        
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.OnRejected = async (context, token) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await context.HttpContext.Response.WriteAsJsonAsync(
                new { status = "Error", message = "Too many requests. Please try again later." }, 
                token);
        };
    });

    builder.Services.AddHttpClient<IBlockchainService, BlockchainService>();
    builder.Services.AddHttpClient("BackendKeepAlive", client =>
    {
        client.Timeout = TimeSpan.FromSeconds(10);
    });
    if (DotnetServiceTopology.RunsKeepAlive(dotnetServiceName))
    {
        builder.Services.AddHostedService<BackendKeepAliveService>();
    }
    builder.Services.AddScoped<IFabricCaAuthService, FabricCaAuthService>();
    builder.Services.AddScoped<IEmailService, EmailService>();
    builder.Services.AddScoped<IAuditLogService, AuditLogService>();
    builder.Services.AddScoped<IAccountProvisioningService, AccountProvisioningService>();
    builder.Services.AddSingleton<IChatMessageEncryption, ChatMessageEncryption>();

    builder.Services.AddHttpClient("FabricCAClient")
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler();
        bool allowInsecure = builder.Environment.IsDevelopment() || 
                             builder.Configuration.GetValue<bool>("Security:AllowInsecureTls");

        if (allowInsecure)
        {
            Log.Warning("internal Fabric CA connection: SSL validation BYPASSED (Development or Config Override)");
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        }
        else
        {
            Log.Information("internal Fabric CA connection: Strict SSL validation ENABLED (Production Mode)");
            handler.ServerCertificateCustomValidationCallback = null; 
        }

        handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                               System.Security.Authentication.SslProtocols.Tls13;
        return handler;
    });

    builder.Services.AddDbContext<RegistrarWriteDbContext>(options =>
    {
        var connectionString = builder.Configuration.GetConnectionString("MasterConnection");
        
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException("PostgreSQL connection string 'MasterConnection' not found in configuration.");
        }
        options.UseNpgsql(connectionString, npgsqlOptions => npgsqlOptions.CommandTimeout((int)TimeSpan.FromMinutes(5).TotalSeconds));
    });

    builder.Services.AddDbContext<RegistrarReadDbContext>(options =>
    {
        var connectionString = builder.Configuration.GetConnectionString("ReplicaConnection");
        
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException("PostgreSQL connection string 'ReplicaConnection' not found in configuration.");
        }
        options.UseNpgsql(connectionString, npgsqlOptions => npgsqlOptions.CommandTimeout((int)TimeSpan.FromMinutes(5).TotalSeconds));
    });

    builder.Services.AddScoped<RegistrarDbContext>(provider => provider.GetRequiredService<RegistrarWriteDbContext>());

    builder.Services.AddSingleton<IChatCache, ChatCache>(); 

    var app = builder.Build();

    app.UseExceptionHandler();
    app.UseSerilogRequestLogging();
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("AllowFrontend");

    app.UseRateLimiter();
    
    if (!app.Environment.IsDevelopment())
    {
        app.UseHsts();
        Log.Information("HSTS enabled (HTTPS Redirection disabled for Nginx)");
    }

    app.UseAuthentication();
    app.UseAuthorization();
    app.MapGet("/health", () => Results.Ok(new
    {
        status = "healthy",
        service = $"dotnet-{dotnetServiceName}-service",
        architecture = dotnetServiceName == DotnetServiceTopology.Monolith ? "monolith" : "microservices"
    }));
    app.MapGet("/api/ready", () => Results.Ok(new
    {
        status = "ready",
        service = $"dotnet-{dotnetServiceName}-service"
    }));
    app.MapGet("/api/backend/health", () => Results.Ok(new
    {
        status = "healthy",
        service = $"dotnet-{dotnetServiceName}-service"
    }));
    app.MapControllers();
    Log.Information("ASP.NET service {ServiceName} configured successfully", dotnetServiceName);
    Log.Information("Listening on {Urls}", string.Join(", ", app.Urls));
    if (DotnetServiceTopology.HostsRealtimeHub(dotnetServiceName))
    {
        app.MapHub<ChatHub>("/chatHub");
        app.MapHub<ChatHub>("/api/chatHub");
    }

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, " Application terminated unexpectedly");
}
finally
{
    await Log.CloseAndFlushAsync();
}
