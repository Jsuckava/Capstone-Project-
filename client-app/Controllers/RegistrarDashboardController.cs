using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Client_app.Controllers
{
    [Authorize(Roles = "registrar,admin")]
    [ApiController]
    [Route("api/[controller]")]
    public class RegistrarDashboardController : ControllerBase
    {
        private readonly string _connectionString;

        public RegistrarDashboardController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? configuration.GetConnectionString("MasterConnection") ?? throw new InvalidOperationException("PostgreSQL connection string not found.");
        }

        [HttpGet("overview")]
        public async Task<IActionResult> GetSystemOverview()
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var deptStats = new List<object>();

                using var cmd = new NpgsqlCommand(@"
                    SELECT 
                        fp.department,
                        COUNT(DISTINCT fp.user_id) as TotalFaculty,
                        (SELECT COUNT(*) FROM pending_grade_records pgr WHERE pgr.course = fp.department AND pgr.status IN ('Finalized', 'DepartmentApproved', 'Issued')) as EncodedGrades,
                        (SELECT COUNT(*) FROM pending_grade_records pgr WHERE pgr.course = fp.department AND pgr.status = 'DepartmentApproved') as PendingApproval
                    FROM FacultyProfiles fp
                    WHERE fp.department IS NOT NULL AND fp.department != 'Unassigned'
                    GROUP BY fp.department", conn);
                
                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    deptStats.Add(new
                    {
                        Department = reader.GetString(0),
                        TotalFaculty = reader.GetInt64(1),
                        EncodedGrades = reader.GetInt64(2),
                        PendingApproval = reader.GetInt64(3)
                    });
                }

                return Ok(deptStats);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("logs/query")]
        public async Task<IActionResult> QueryActivityLogs([FromQuery] DateTime? from, [FromQuery] DateTime? to)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var logs = new List<object>();
                var fromDate = from ?? DateTime.UtcNow.AddDays(-30);
                var toDate = to ?? DateTime.UtcNow;

                using var cmd = new NpgsqlCommand(@"
                    SELECT logid, recordid, oldgrade, newgrade, reasontext, approvedby, timestamp 
                    FROM gradecorrectionlogs 
                    WHERE timestamp >= @from AND timestamp <= @to
                    ORDER BY timestamp DESC", conn);
                
                cmd.Parameters.AddWithValue("from", fromDate);
                cmd.Parameters.AddWithValue("to", toDate);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    logs.Add(new {
                        id = reader.GetInt32(0),
                        recordId = reader.IsDBNull(1) ? null : reader.GetString(1),
                        oldGrade = reader.IsDBNull(2) ? null : reader.GetString(2),
                        newGrade = reader.IsDBNull(3) ? null : reader.GetString(3),
                        reason = reader.IsDBNull(4) ? null : reader.GetString(4),
                        approvedBy = reader.IsDBNull(5) ? null : reader.GetString(5),
                        timestamp = reader.GetDateTime(6)
                    });
                }

                return Ok(logs);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }
    }
}