using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Npgsql;
using For_Testing_Only_Capstone.Models;
using System;
using System.Collections.Generic;
using System.IO;
using ClosedXML.Excel;
using System.Text.Json;
using System.Threading.Tasks;

namespace Client_app.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class GradeTemplateController : ControllerBase
    {
        private readonly string _writeConnectionString;
        private readonly string _readConnectionString;

        public GradeTemplateController(IConfiguration configuration)
        {
            _writeConnectionString = configuration.GetConnectionString("MasterConnection") ?? configuration.GetConnectionString("PostgresConnection") ?? throw new InvalidOperationException("Database connection string not found.");
            _readConnectionString = configuration.GetConnectionString("ReplicaConnection") ?? configuration.GetConnectionString("PostgresConnection") ?? throw new InvalidOperationException("Database connection string not found.");
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateTemplate([FromBody] CreateTemplateRequest request)
        {
            if (string.IsNullOrEmpty(request.TemplateName) || string.IsNullOrEmpty(request.Department))
                return BadRequest(new { status = "Error", message = "Template name and target department are required." });

            try
            {
                using var conn = new NpgsqlConnection(_writeConnectionString);
                await conn.OpenAsync();

                string query = @"
                    INSERT INTO GradeTemplates (template_name, department, formula_config, status, created_at)
                    VALUES (@name, @dept, @config, 'Pending', @time) RETURNING id";
                
                using var cmd = new NpgsqlCommand(query, conn);
                cmd.Parameters.AddWithValue("name", request.TemplateName);
                cmd.Parameters.AddWithValue("dept", request.Department);
                cmd.Parameters.AddWithValue("config", JsonSerializer.Serialize(request.FormulaConfig));
                cmd.Parameters.AddWithValue("time", DateTime.UtcNow);

                int newId = (int)(await cmd.ExecuteScalarAsync() ?? 0);

                return Ok(new { status = "Success", message = $"Template created successfully and is pending approval from the {request.Department} department.", templateId = newId });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = $"Database error: {ex.Message}" });
            }
        }

        [HttpGet("department/{department}")]
        public async Task<IActionResult> GetDepartmentTemplates(string department)
        {
            try
            {
                using var conn = new NpgsqlConnection(_readConnectionString);
                await conn.OpenAsync();

                var templates = new List<object>();
                using var cmd = new NpgsqlCommand("SELECT id, template_name, formula_config, status, created_at FROM GradeTemplates WHERE department = @dept", conn);
                cmd.Parameters.AddWithValue("dept", department);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    templates.Add(new {
                        id = reader.GetInt32(0),
                        templateName = reader.GetString(1),
                        formulaConfig = JsonDocument.Parse(reader.GetString(2)),
                        status = reader.GetString(3),
                        createdAt = reader.GetDateTime(4)
                    });
                }

                return Ok(new { status = "Success", templates });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPut("{id}/review")]
        public async Task<IActionResult> ReviewTemplate(int id, [FromBody] ReviewTemplateRequest request)
        {
            if (request.Status != "Approved" && request.Status != "Rejected")
                return BadRequest(new { status = "Error", message = "Status must be either 'Approved' or 'Rejected'." });

            try
            {
                using var conn = new NpgsqlConnection(_writeConnectionString);
                await conn.OpenAsync();

                using var cmd = new NpgsqlCommand("UPDATE GradeTemplates SET status = @status WHERE id = @id", conn);
                cmd.Parameters.AddWithValue("status", request.Status);
                cmd.Parameters.AddWithValue("id", id);

                int rows = await cmd.ExecuteNonQueryAsync();
                if (rows == 0) return NotFound(new { status = "Error", message = "Template not found." });

                return Ok(new { status = "Success", message = $"Template has been {request.Status.ToLower()}." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("department/{department}/section/{section}/download")]
        public async Task<IActionResult> DownloadGradingSheet(string department, string section)
        {
            try
            {
                using var conn = new NpgsqlConnection(_readConnectionString);
                await conn.OpenAsync();

                // 1. Dynamically resolve the true department of this section to support cross-department teaching
                using var cmdResolveDept = new NpgsqlCommand("SELECT department FROM StudentProfiles WHERE section = @section AND department IS NOT NULL LIMIT 1", conn);
                cmdResolveDept.Parameters.AddWithValue("section", section);
                var resolvedDept = await cmdResolveDept.ExecuteScalarAsync() as string;
                
                string targetDepartment = !string.IsNullOrEmpty(resolvedDept) ? resolvedDept : department;

                // 2. Fetch the latest Approved Template for the resolved target department
                using var cmdTemplate = new NpgsqlCommand(@"
                    SELECT formula_config FROM GradeTemplates 
                    WHERE department = @dept AND status = 'Approved' 
                    ORDER BY created_at DESC LIMIT 1", conn);
                cmdTemplate.Parameters.AddWithValue("dept", targetDepartment);

                var configJson = (string?)await cmdTemplate.ExecuteScalarAsync();
                if (string.IsNullOrEmpty(configJson))
                    return NotFound(new { status = "Error", message = $"No approved grading template found for the {targetDepartment} department." });

                var config = JsonSerializer.Deserialize<FormulaConfig>(configJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (config == null || config.Columns == null)
                    return StatusCode(500, new { status = "Error", message = "Invalid template configuration format." });

                // 3. Fetch Enrolled Students for this section
                var students = new List<StudentRow>();
                using var cmdStudents = new NpgsqlCommand(@"
                    SELECT full_name, student_no FROM StudentProfiles 
                    WHERE department = @dept AND section = @section AND assignment_status = 'Enrolled'
                    ORDER BY full_name ASC", conn);
                cmdStudents.Parameters.AddWithValue("dept", targetDepartment);
                cmdStudents.Parameters.AddWithValue("section", section);

                using var reader = await cmdStudents.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    students.Add(new StudentRow {
                        FullName = reader.GetString(0),
                        StudentNo = reader.IsDBNull(1) ? "N/A" : reader.GetString(1)
                    });
                }
                await reader.CloseAsync();

                // 4. Build the Excel File dynamically using ClosedXML
                using var workbook = new XLWorkbook();
                var ws = workbook.Worksheets.Add($"Section {section}");

                // Set Headers
                ws.Cell(1, 1).Value = "Full Name";
                ws.Cell(1, 2).Value = "Student No";
                
                for (int i = 0; i < config.Columns.Count; i++)
                {
                    ws.Cell(1, i + 3).Value = config.Columns[i].Header;
                }

                // Populate Data and Formulas
                for (int r = 0; r < students.Count; r++)
                {
                    int rowNum = r + 2; // Excel rows are 1-indexed, Row 1 is header
                    ws.Cell(rowNum, 1).Value = students[r].FullName;
                    ws.Cell(rowNum, 2).Value = students[r].StudentNo;

                    for (int c = 0; c < config.Columns.Count; c++)
                    {
                        int colNum = c + 3;
                        var columnDef = config.Columns[c];
                        
                        if (columnDef.Type?.ToLower() == "formula" && !string.IsNullOrEmpty(columnDef.Value))
                        {
                            // Replace the {row} placeholder with the actual Excel row number (e.g. "=(C{row} * 0.5)" -> "=(C2 * 0.5)")
                            string excelFormula = columnDef.Value.Replace("{row}", rowNum.ToString());
                            ws.Cell(rowNum, colNum).FormulaA1 = excelFormula;
                        }
                    }
                }

                // Format the sheet slightly
                ws.Columns().AdjustToContents();
                ws.Range(1, 1, 1, config.Columns.Count + 2).Style.Font.Bold = true;

                // 4. Return as File Download
                using var stream = new MemoryStream();
                workbook.SaveAs(stream);
                var content = stream.ToArray();
                
                string safeSection = string.Join("_", section.Split(Path.GetInvalidFileNameChars()));
                return File(content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", $"{targetDepartment}_Sec_{safeSection}_Grades.xlsx");
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = $"Excel generation failed: {ex.Message}" });
            }
        }
    }

    public class CreateTemplateRequest
    {
        public string TemplateName { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public object FormulaConfig { get; set; } = new object();
    }

    public class ReviewTemplateRequest
    {
        public string Status { get; set; } = string.Empty; // "Approved" or "Rejected"
    }

    // --- JSON Mapping Classes ---
    public class FormulaConfig
    {
        public List<TemplateColumn> Columns { get; set; } = new List<TemplateColumn>();
    }

    public class TemplateColumn
    {
        public string Id { get; set; } = string.Empty; // e.g. "C", "D"
        public string Header { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // "input" or "formula"
        public string Value { get; set; } = string.Empty; // e.g. "=(C{row}*0.5) + (D{row}*0.5)"
    }

    public class StudentRow 
    {
        public string FullName { get; set; } = string.Empty;
        public string StudentNo { get; set; } = string.Empty;
    }
}