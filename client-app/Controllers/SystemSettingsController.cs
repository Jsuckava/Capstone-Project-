using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.SignalR;

namespace Client_app.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class SystemSettingsController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly ILogger<SystemSettingsController> _logger;
        private readonly IHubContext<ChatHub> _chatHubContext;
        private static readonly object SchemaInitializationLock = new();
        private static bool _schemaInitialized;

        public SystemSettingsController(IConfiguration configuration, ILogger<SystemSettingsController> logger, IHubContext<ChatHub> chatHubContext)
        {
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? configuration.GetConnectionString("MasterConnection") ?? throw new InvalidOperationException("PostgreSQL connection string not found.");
            _logger = logger;
            _chatHubContext = chatHubContext;
            EnsureTableExists();
        }

        private void EnsureTableExists()
        {
            if (System.Threading.Volatile.Read(ref _schemaInitialized)) return;
            lock (SchemaInitializationLock)
            {
                if (System.Threading.Volatile.Read(ref _schemaInitialized)) return;
                try
                {
                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();
                    using var cmd = new NpgsqlCommand(@"
                        CREATE TABLE IF NOT EXISTS SystemSettings (
                            key VARCHAR(255) PRIMARY KEY,
                            value TEXT NOT NULL
                        );", conn);
                    cmd.ExecuteNonQuery();
                    System.Threading.Volatile.Write(ref _schemaInitialized, true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "System settings schema initialization was deferred.");
                }
            }
        }

        public class SettingRequest
        {
            public string Key { get; set; } = string.Empty;
            public string Value { get; set; } = string.Empty;
        }

        [HttpGet("{key}")]
        public async Task<IActionResult> GetSetting(string key)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand("SELECT value FROM SystemSettings WHERE key = @k", conn);
                cmd.Parameters.AddWithValue("k", key);
                var value = await cmd.ExecuteScalarAsync();
                if (value != null)
                {
                    return Ok(new { status = "Success", value = value.ToString() });
                }
                return NotFound(new { status = "Error", message = "Setting not found." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost]
        [Authorize(Roles = "registrar,admin")]
        public async Task<IActionResult> SaveSetting([FromBody] SettingRequest req)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand(@"
                    INSERT INTO SystemSettings (key, value) VALUES (@k, @v) 
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", conn);
                cmd.Parameters.AddWithValue("k", req.Key);
                cmd.Parameters.AddWithValue("v", req.Value);
                await cmd.ExecuteNonQueryAsync();
                await _chatHubContext.Clients.All.SendAsync("SystemSettingChanged", new
                {
                    Key = req.Key,
                    Value = req.Value,
                    UpdatedAt = DateTime.UtcNow
                });
                return Ok(new { status = "Success" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost("reset-season")]
        [Authorize(Roles = "registrar,admin")]
        public async Task<IActionResult> ResetEncodingSeason()
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var tx = await conn.BeginTransactionAsync();

                using var cmdClearGrades = new NpgsqlCommand("DELETE FROM pending_grade_records", conn, tx);
                await cmdClearGrades.ExecuteNonQueryAsync();

                using var cmdClearFacSections = new NpgsqlCommand("DELETE FROM FacultySections", conn, tx);
                await cmdClearFacSections.ExecuteNonQueryAsync();

                const string resetEncodingPeriod = "{\"semester\":\"2nd Semester\",\"startDate\":\"\",\"endDate\":\"\",\"term\":\"midterm\"}";
                using var cmdResetEncodingPeriod = new NpgsqlCommand(@"
                    INSERT INTO SystemSettings (key, value) VALUES ('encoding_period', @value)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", conn, tx);
                cmdResetEncodingPeriod.Parameters.AddWithValue("value", resetEncodingPeriod);
                await cmdResetEncodingPeriod.ExecuteNonQueryAsync();

                await tx.CommitAsync();

                _logger.LogInformation("Encoding season reset by {User}", User.Identity?.Name);
                await _chatHubContext.Clients.All.SendAsync("SystemSettingChanged", new
                {
                    Key = "encoding_period",
                    Value = resetEncodingPeriod,
                    UpdatedAt = DateTime.UtcNow
                });

                return Ok(new
                {
                    status = "Success",
                    message = "Encoding season reset. Faculty assigned sections were cleared while saved sections were kept."
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = $"Failed to reset season: {ex.Message}" });
            }
        }
    }
}
