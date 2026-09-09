using Npgsql;

namespace Client_app.Services
{
    /// <summary>
    /// Periodically exercises the database and middleware readiness paths so stale
    /// pooled connections are discovered and rebuilt before the next user request.
    /// </summary>
    public sealed class BackendKeepAliveService : BackgroundService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<BackendKeepAliveService> _logger;

        public BackendKeepAliveService(
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            ILogger<BackendKeepAliveService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_configuration.GetValue("KeepAlive:Enabled", true)) return;

            var intervalSeconds = Math.Max(15, _configuration.GetValue("KeepAlive:IntervalSeconds", 45));
            var initialDelaySeconds = Math.Max(1, _configuration.GetValue("KeepAlive:InitialDelaySeconds", 10));
            await Task.Delay(TimeSpan.FromSeconds(initialDelaySeconds), stoppingToken);

            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds));
            do
            {
                await ProbeDependencies(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }

        private async Task ProbeDependencies(CancellationToken cancellationToken)
        {
            try
            {
                var connectionString = _configuration.GetConnectionString("MasterConnection")
                    ?? _configuration.GetConnectionString("PostgresConnection");
                if (!string.IsNullOrWhiteSpace(connectionString))
                {
                    await using var connection = new NpgsqlConnection(connectionString);
                    await connection.OpenAsync(cancellationToken);
                    await using var command = new NpgsqlCommand("SELECT 1", connection);
                    await command.ExecuteScalarAsync(cancellationToken);
                }

                var middlewareUrl = (_configuration["Middleware:Url"]
                    ?? _configuration["MIDDLEWARE_URL"]
                    ?? "http://127.0.0.1:4000").TrimEnd('/');
                var client = _httpClientFactory.CreateClient("BackendKeepAlive");
                using var response = await client.GetAsync($"{middlewareUrl}/api/ready", cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Backend keepalive received HTTP {StatusCode} from middleware readiness.", (int)response.StatusCode);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Normal application shutdown.
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Backend keepalive detected an unavailable dependency; the next interval will retry.");
            }
        }
    }
}
