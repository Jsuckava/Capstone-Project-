using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Client_app.Models;

namespace Client_app.Controllers
{
    [ApiController]
    [Route("api/registrar/[controller]")]
    public class SearchController : ControllerBase
    {
        private readonly string _connectionString;

        public SearchController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? 
                throw new InvalidOperationException("PostgreSQL connection string not found.");
        }

        [HttpGet]
        public async Task<IActionResult> SearchUsers([FromQuery] string type, [FromQuery] string query)
        {
            if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(query))
            {
                return BadRequest(new { status = "Error", message = "type (student/faculty) and query required." });
            }

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var results = new List<object>();
                string sql = "";

                if (type.ToLower() == "student")
                {
                    sql = @"
                        SELECT u.id, sp.full_name, u.email, sp.student_no, sp.department, sp.section, sp.date_of_birth
                        FROM Users u 
                        JOIN StudentProfiles sp ON u.id = sp.user_id 
                        WHERE u.role = 'student' AND u.status = 'APPROVED'
                        AND (LOWER(sp.full_name) LIKE @query 
                             OR LOWER(u.email) LIKE @query 
                             OR LOWER(sp.student_no) LIKE @query 
                             OR LOWER(sp.department) LIKE @query)";
                }
                else if (type.ToLower() == "faculty")
                {
                    sql = @"
                        SELECT u.id, fp.full_name, u.email, fp.department
                        FROM Users u 
                        JOIN FacultyProfiles fp ON u.id = fp.user_id 
                        WHERE u.role = 'faculty' AND u.status = 'APPROVED'
                        AND (LOWER(fp.full_name) LIKE @query 
                             OR LOWER(u.email) LIKE @query 
                             OR LOWER(fp.department) LIKE @query)";
                }
                else
                {
                    return BadRequest(new { status = "Error", message = "Invalid type. Use 'student' or 'faculty'." });
                }

                using var cmd = new NpgsqlCommand(sql, conn);
                cmd.Parameters.AddWithValue("query", $"%{query.ToLower()}%");

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    if (type.ToLower() == "student")
                    {
                        results.Add(new {
                            id = reader.GetInt32(0),
                            fullName = reader.GetString(1),
                            email = reader.GetString(2),
                            studentNo = reader.IsDBNull(3) ? null : reader.GetString(3),
                            department = reader.IsDBNull(4) ? null : reader.GetString(4),
                            section = reader.IsDBNull(5) ? null : reader.GetString(5),
                            dateOfBirth = reader.IsDBNull(6) ? null : reader.GetDateTime(6).ToString("MM/dd/yyyy")
                        });
                    }
                    else
                    {
                        results.Add(new {
                            id = reader.GetInt32(0),
                            fullName = reader.GetString(1),
                            email = reader.GetString(2),
                            department = reader.IsDBNull(3) ? null : reader.GetString(3)
                        });
                    }
                }

                return Ok(new { status = "Success", results, count = results.Count });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }
    }
}
