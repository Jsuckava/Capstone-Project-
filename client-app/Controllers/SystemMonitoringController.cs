using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Npgsql;

namespace Client_app.Controllers
{
    [ApiController]
    [Authorize(Roles = "system_admin")]
    [Route("api/[controller]")]
    public sealed class SystemMonitoringController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly string _middlewareUrl;
        private readonly string? _prometheusUrl;
        private readonly string _grafanaUrl;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IMemoryCache _cache;
        private const string GrafanaSessionCookie = "blockgo_grafana_session";

        public SystemMonitoringController(IConfiguration configuration, IHttpClientFactory httpClientFactory, IMemoryCache cache)
        {
            _connectionString = configuration.GetConnectionString("MasterConnection")
                ?? configuration.GetConnectionString("PostgresConnection")
                ?? throw new InvalidOperationException("A PostgreSQL connection is required.");
            _middlewareUrl = configuration["Middleware:Url"] ?? "http://middleware:4000";
            _prometheusUrl = configuration["Monitoring:PrometheusUrl"] ?? Environment.GetEnvironmentVariable("PROMETHEUS_URL");
            _grafanaUrl = configuration["Monitoring:GrafanaUrl"]
                ?? Environment.GetEnvironmentVariable("GRAFANA_URL")
                ?? "http://grafana.plv-fabric.svc.cluster.local:3000";
            _httpClientFactory = httpClientFactory;
            _cache = cache;
        }

        [HttpPost("grafana/session")]
        public IActionResult CreateGrafanaSession()
        {
            var sessionToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var cacheKey = GrafanaCacheKey(sessionToken);
            var actor = User.Identity?.Name ?? "system-admin@blockgo.local";
            _cache.Set(cacheKey, actor, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(8),
                SlidingExpiration = TimeSpan.FromMinutes(30)
            });
            Response.Cookies.Append(GrafanaSessionCookie, sessionToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Strict,
                Path = "/api/SystemMonitoring/grafana",
                MaxAge = TimeSpan.FromMinutes(30),
                IsEssential = true
            });
            return Ok(new { status = "Success", url = "/api/SystemMonitoring/grafana/" });
        }

        [AllowAnonymous]
        [AcceptVerbs("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")]
        [Route("grafana/{**path}")]
        public async Task ProxyGrafana(string? path, CancellationToken cancellationToken)
        {
            if (!TryGetGrafanaActor(out var actor))
            {
                Response.StatusCode = StatusCodes.Status401Unauthorized;
                await Response.WriteAsJsonAsync(new { status = "Error", message = "A System Admin Grafana session is required." }, cancellationToken);
                return;
            }

            var relativePath = (path ?? string.Empty).TrimStart('/');
            if (relativePath.Contains("://", StringComparison.Ordinal) || relativePath.Contains("..", StringComparison.Ordinal))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            // Grafana is configured with serve_from_sub_path at this public route. Forwarding
            // only the captured remainder makes Grafana redirect to its configured root URL;
            // HttpClient then follows that public localhost redirect from inside this pod and
            // fails with connection refused. Preserve the configured subpath on the upstream
            // request so Grafana serves the resource directly.
            var targetUrl = $"{_grafanaUrl.TrimEnd('/')}/api/SystemMonitoring/grafana/{relativePath}{Request.QueryString}";
            using var proxyRequest = new HttpRequestMessage(new HttpMethod(Request.Method), targetUrl);
            var requestHasBody = Request.ContentLength.GetValueOrDefault() > 0 || Request.Headers.ContainsKey("Transfer-Encoding");
            if (requestHasBody) proxyRequest.Content = new StreamContent(Request.Body);

            foreach (var header in Request.Headers)
            {
                if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("X-WEBAUTH-USER", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("X-WEBAUTH-NAME", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("X-Forwarded-Prefix", StringComparison.OrdinalIgnoreCase)) continue;
                if (!proxyRequest.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                    proxyRequest.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
            proxyRequest.Headers.TryAddWithoutValidation("X-WEBAUTH-USER", actor);
            proxyRequest.Headers.TryAddWithoutValidation("X-WEBAUTH-NAME", "BlockGO System Administrator");
            proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Prefix", "/api/SystemMonitoring/grafana");

            using var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromMinutes(5);
            using var proxyResponse = await client.SendAsync(proxyRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            Response.StatusCode = (int)proxyResponse.StatusCode;
            foreach (var header in proxyResponse.Headers)
                Response.Headers.Append(header.Key, header.Value.ToArray());
            foreach (var header in proxyResponse.Content.Headers)
                Response.Headers.Append(header.Key, header.Value.ToArray());
            Response.Headers.Remove("transfer-encoding");
            Response.Headers.Remove("connection");
            await proxyResponse.Content.CopyToAsync(Response.Body, cancellationToken);
        }

        [HttpGet("summary")]
        public async Task<IActionResult> Summary(CancellationToken cancellationToken)
        {
            var services = new List<object>();
            var database = new { status = "down", name = "", sizeBytes = (long?)null, activeConnections = (long?)null };
            var dbStopwatch = Stopwatch.StartNew();
            try
            {
                await using var connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);
                await using var command = new NpgsqlCommand(@"
                    SELECT current_database(), pg_database_size(current_database()),
                           (SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database());", connection);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                await reader.ReadAsync(cancellationToken);
                database = new { status = "healthy", name = reader.GetString(0), sizeBytes = (long?)reader.GetInt64(1), activeConnections = (long?)reader.GetInt64(2) };
                services.Add(Service("postgres", "PostgreSQL", "Data", "healthy", dbStopwatch.ElapsedMilliseconds, "Database query completed.", "PostgreSQL"));
            }
            catch (Exception exception)
            {
                services.Add(Service("postgres", "PostgreSQL", "Data", "down", dbStopwatch.ElapsedMilliseconds, SafeMessage(exception), "PostgreSQL"));
            }

            var middlewareStopwatch = Stopwatch.StartNew();
            try
            {
                using var client = _httpClientFactory.CreateClient();
                client.Timeout = TimeSpan.FromSeconds(4);
                using var response = await client.GetAsync($"{_middlewareUrl.TrimEnd('/')}/api/ready", cancellationToken);
                services.Add(Service("middleware", "Fabric Middleware", "Application", response.IsSuccessStatusCode ? "healthy" : "down",
                    middlewareStopwatch.ElapsedMilliseconds, $"HTTP {(int)response.StatusCode}", _middlewareUrl));
            }
            catch (Exception exception)
            {
                services.Add(Service("middleware", "Fabric Middleware", "Application", "down", middlewareStopwatch.ElapsedMilliseconds, SafeMessage(exception), _middlewareUrl));
            }

            services.Insert(0, Service("backend", "ASP.NET Core API", "Application", "healthy", 0, "Monitoring endpoint is responsive.", HttpContext.Request.Host.Value));
            var alerts = await LoadSecurityAlertsAsync(cancellationToken);
            var prometheusAvailable = false;
            if (!string.IsNullOrWhiteSpace(_prometheusUrl))
            {
                try
                {
                    using var client = _httpClientFactory.CreateClient();
                    client.Timeout = TimeSpan.FromSeconds(4);
                    using var response = await client.GetAsync($"{_prometheusUrl.TrimEnd('/')}/api/v1/alerts", cancellationToken);
                    prometheusAvailable = response.IsSuccessStatusCode;
                    if (response.IsSuccessStatusCode)
                    {
                        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                        if (document.RootElement.TryGetProperty("data", out var data) && data.TryGetProperty("alerts", out var items))
                        {
                            foreach (var item in items.EnumerateArray())
                            {
                                var labels = item.TryGetProperty("labels", out var labelValue) ? labelValue : default;
                                var annotations = item.TryGetProperty("annotations", out var annotationValue) ? annotationValue : default;
                                alerts.Add(new
                                {
                                    name = JsonText(labels, "alertname", "Prometheus Alert"),
                                    severity = JsonText(labels, "severity", "warning"),
                                    component = JsonText(labels, "component", "infrastructure"),
                                    summary = JsonText(annotations, "summary", "An infrastructure alert is active.")
                                });
                            }
                        }
                    }
                }
                catch { }
            }

            var process = Process.GetCurrentProcess();
            var serviceStatuses = services.Select(item => JsonSerializer.Serialize(item)).ToArray();
            var hasDownService = serviceStatuses.Any(item => item.Contains("\"status\":\"down\"", StringComparison.Ordinal));
            var hasCriticalAlert = alerts.Any(item => JsonSerializer.Serialize(item).Contains("\"severity\":\"critical\"", StringComparison.OrdinalIgnoreCase));
            return Ok(new
            {
                generatedAt = DateTimeOffset.UtcNow,
                status = hasDownService ? "down" : hasCriticalAlert || alerts.Count > 0 ? "warning" : "healthy",
                services,
                database,
                runtime = new
                {
                    uptimeSeconds = (DateTime.UtcNow - process.StartTime.ToUniversalTime()).TotalSeconds,
                    workingSetBytes = process.WorkingSet64,
                    managedMemoryBytes = GC.GetTotalMemory(false),
                    threadCount = process.Threads.Count,
                    processorCount = Environment.ProcessorCount
                },
                infrastructure = new
                {
                    source = prometheusAvailable ? "prometheus" : "runtime",
                    cpuCores = (double?)null,
                    memoryBytes = (long?)null,
                    runningPods = (long?)null,
                    healthyFabricTargets = services.Count(item => JsonSerializer.Serialize(item).Contains("Fabric Middleware") && JsonSerializer.Serialize(item).Contains("healthy"))
                },
                alerts
            });
        }

        [HttpPost("security-events/{eventId:long}/resolve")]
        public async Task<IActionResult> ResolveSecurityEvent(long eventId, CancellationToken cancellationToken)
        {
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = new NpgsqlCommand(@"
                UPDATE security_events
                SET resolved_at = CURRENT_TIMESTAMP,
                    resolved_by = (SELECT id FROM users WHERE LOWER(email) = LOWER(@actor))
                WHERE security_event_id = @eventId AND resolved_at IS NULL
                RETURNING security_event_id;", connection);
            command.Parameters.AddWithValue("actor", User.Identity?.Name ?? string.Empty);
            command.Parameters.AddWithValue("eventId", eventId);
            if (await command.ExecuteScalarAsync(cancellationToken) is null) return NotFound(new { status = "Error", message = "Open security event not found." });
            return Ok(new { status = "Success", message = "Security event resolved." });
        }

        private async Task<List<object>> LoadSecurityAlertsAsync(CancellationToken cancellationToken)
        {
            var alerts = new List<object>();
            try
            {
                await using var connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);
                await using var command = new NpgsqlCommand(@"
                    SELECT security_event_id, event_type, severity, attempted_identity, ip_address, details, created_at
                    FROM security_events
                    WHERE resolved_at IS NULL AND created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
                    ORDER BY created_at DESC LIMIT 100;", connection);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    var severity = reader.GetString(2).ToLowerInvariant();
                    alerts.Add(new
                    {
                        eventId = reader.GetInt64(0), name = reader.GetString(1).Replace('_', ' '),
                        severity = severity is "critical" or "high" ? "critical" : "warning",
                        component = "access-control",
                        summary = $"{(reader.IsDBNull(3) ? "Unknown identity" : reader.GetString(3))} from {(reader.IsDBNull(4) ? "unknown IP" : reader.GetString(4))}: {(reader.IsDBNull(5) ? "Access attempt denied." : reader.GetString(5))}",
                        occurredAt = reader.GetFieldValue<DateTimeOffset>(6)
                    });
                }
            }
            catch { }
            return alerts;
        }

        private static object Service(string id, string name, string layer, string status, long latencyMs, string message, string target) =>
            new { id, name, layer, status, latencyMs, message, target };
        private static string SafeMessage(Exception exception) => exception is TaskCanceledException ? "Health check timed out." : exception.Message;
        private static string JsonText(JsonElement element, string property, string fallback) =>
            element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) ? value.ToString() : fallback;

        private bool TryGetGrafanaActor(out string actor)
        {
            actor = string.Empty;
            return Request.Cookies.TryGetValue(GrafanaSessionCookie, out var sessionToken)
                && !string.IsNullOrWhiteSpace(sessionToken)
                && _cache.TryGetValue(GrafanaCacheKey(sessionToken), out actor!)
                && !string.IsNullOrWhiteSpace(actor);
        }

        private static string GrafanaCacheKey(string sessionToken)
        {
            var digest = SHA256.HashData(Encoding.UTF8.GetBytes(sessionToken));
            return $"system-admin:grafana:{Convert.ToHexString(digest)}";
        }
    }
}
