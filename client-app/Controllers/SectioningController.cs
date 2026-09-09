using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.Threading.Tasks;
using System.Text.Json;

namespace Client_app.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class SectioningController : ControllerBase
    {
        private readonly string _connectionString;

        public SectioningController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? 
                                configuration.GetConnectionString("MasterConnection") ?? 
                                throw new InvalidOperationException("PostgreSQL connection string not found.");
        }

        private async Task<IActionResult> GetData(string key)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand("SELECT data_json FROM SectioningState WHERE key = @k", conn);
                cmd.Parameters.AddWithValue("k", key);
                var json = await cmd.ExecuteScalarAsync() as string;
                
                return string.IsNullOrEmpty(json) ? Ok(new object[] { }) : Content(json, "application/json");
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        private async Task<IActionResult> SaveData(string key, [FromBody] JsonElement data)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand(@"
                    INSERT INTO SectioningState (key, data_json, updated_at) 
                    VALUES (@k, @d::jsonb, CURRENT_TIMESTAMP)
                    ON CONFLICT (key) DO UPDATE SET data_json = EXCLUDED.data_json, updated_at = CURRENT_TIMESTAMP;", conn);
                cmd.Parameters.AddWithValue("k", key);
                cmd.Parameters.AddWithValue("d", data.GetRawText());
                await cmd.ExecuteNonQueryAsync();
                
                return Ok(new { status = "Success" });
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        [HttpGet("batches")] public Task<IActionResult> GetBatches() => GetData("batches");
        [HttpPost("batches")] public Task<IActionResult> SaveBatches([FromBody] JsonElement data) => SaveData("batches", data);

        [HttpGet("graduating")] public Task<IActionResult> GetGraduating() => GetData("graduating");
        [HttpPost("graduating")] public Task<IActionResult> SaveGraduating([FromBody] JsonElement data) => SaveData("graduating", data);

        [HttpGet("irregular")] public Task<IActionResult> GetIrregular() => GetData("irregular");
        [HttpPost("irregular")] public Task<IActionResult> SaveIrregular([FromBody] JsonElement data) => SaveData("irregular", data);

        [HttpGet("assignments")] public Task<IActionResult> GetAssignments() => GetData("assignments");
        [HttpPost("assignments")] public Task<IActionResult> SaveAssignments([FromBody] JsonElement data) => SaveData("assignments", data);
    }
}
