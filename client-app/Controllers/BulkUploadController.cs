using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Npgsql;
using ClosedXML.Excel;
using BlockGo.Models;
using BlockGo.Services;
using BlockGo.Mappers;

namespace BlockGo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class BulkUploadController : ControllerBase
    {
        private readonly ILogger<BulkUploadController> _logger;
        private readonly IBlockchainService _blockchainService;
        private readonly string _connectionString;

        public BulkUploadController(ILogger<BulkUploadController> logger, IBlockchainService blockchainService, IConfiguration configuration)
        {
            _logger = logger;
            _blockchainService = blockchainService;
            _connectionString = configuration.GetConnectionString("MasterConnection") ?? configuration.GetConnectionString("DefaultConnection") ?? "";
        }

        private string HashIdentifier(string input)
        {
            if (string.IsNullOrEmpty(input)) return "Unknown";
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input.Trim().ToLower()));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private string MaskHash(string hash)
        {
            if (string.IsNullOrEmpty(hash) || hash.Length < 12) return hash;
            return hash.Substring(0, 8) + "..." + hash.Substring(hash.Length - 4);
        }

        private static string[] ParseCsvLine(string line)
        {
            var fields = new List<string>();
            var current = new StringBuilder();
            var inQuotes = false;

            for (int i = 0; i < line.Length; i++)
            {
                var c = line[i];
                if (c == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == ',' && !inQuotes)
                {
                    fields.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }

            fields.Add(current.ToString());
            return fields.ToArray();
        }

        [HttpPost("bulk-upload")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> BulkUploadGrades([FromForm] IFormFile file, [FromForm] string? semester, [FromForm] string? schoolYear, [FromForm] string? yearLevel, [FromForm] string? section)
        {
            _logger.LogInformation("Bulk upload initiated by: {User}", User.Identity?.Name);
            
            if (file == null || file.Length == 0)
                return BadRequest(new { status = "Error", message = "File required" });

            var facultyEmail = User.Identity?.Name;
            if (string.IsNullOrEmpty(facultyEmail))
                return Unauthorized();

            try
            {
                var ext = Path.GetExtension(file.FileName).ToLower();
                if (ext != ".csv" && ext != ".xlsx")
                    return BadRequest(new { status = "Error", message = "Only .csv and .xlsx files are supported." });

                var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ext);
                var batchId = Guid.NewGuid().ToString();

                try
                {
                    using (var fileStream = new FileStream(tempFile, FileMode.Create))
                        await file.CopyToAsync(fileStream);

                    using var conn = new NpgsqlConnection(_connectionString);
                    await conn.OpenAsync();
                    int count = 0;

                    if (ext == ".csv") {
                        using var reader = new StreamReader(tempFile);
                        var header = await reader.ReadLineAsync();
                        var headerFields = header == null
                            ? new List<string>()
                            : ParseCsvLine(header).Select(f => f?.Trim().ToLower().Replace(" ", "_") ?? "").ToList();
                        
                        while (!reader.EndOfStream) {
                            var line = await reader.ReadLineAsync();
                            if (string.IsNullOrEmpty(line)) continue;
                            var parts = ParseCsvLine(line);
                            if (parts.Length < 2) continue;

                            var getVal = (string col) => {
                                var idx = headerFields?.IndexOf(col) ?? -1;
                                return (idx >= 0 && idx < parts.Length) ? parts[idx]?.Trim() : null;
                            };

                            var studentId = getVal("student_id") ?? getVal("student_no") ?? parts[0];
                            var grade = getVal("grade") ?? getVal("final_grade") ?? parts[1];
                            var hashedStudentId = HashIdentifier(studentId);
                            var subjectCode = getVal("subject_code") ?? "Unknown";
                            var sem = semester ?? getVal("semester") ?? "Unknown";
                            var sy = schoolYear ?? getVal("school_year") ?? "Unknown";
                            
                            // Idempotency check (WBSD 1.4.2 & 1.5.2)
                            using var cmdCheck = new NpgsqlCommand("SELECT COUNT(1) FROM bulk_grade_staging WHERE student_hash = @sh AND subject_code = @sub AND semester = @sem AND school_year = @sy", conn);
                            cmdCheck.Parameters.AddWithValue("sh", hashedStudentId);
                            cmdCheck.Parameters.AddWithValue("sub", subjectCode);
                            cmdCheck.Parameters.AddWithValue("sem", sem);
                            cmdCheck.Parameters.AddWithValue("sy", sy);
                            long exists = (long)(await cmdCheck.ExecuteScalarAsync() ?? 0);
                            if (exists > 0) continue;

                            using var cmd = new NpgsqlCommand(@"
                                INSERT INTO bulk_grade_staging (batch_id, student_hash, course, subject_code, subject_name, grade, semester, school_year, year_level, section, faculty_id, status)
                                VALUES (@bid, @sid, @course, @sub, @subn, @grade, @sem, @sy, @yl, @sec, @fid, 'PENDING_APPROVAL')", conn);
                            
                            cmd.Parameters.AddWithValue("bid", batchId);
                            cmd.Parameters.AddWithValue("sid", hashedStudentId);
                            cmd.Parameters.AddWithValue("course", getVal("course") ?? getVal("department") ?? "Unknown");
                            cmd.Parameters.AddWithValue("sub", subjectCode);
                            cmd.Parameters.AddWithValue("subn", getVal("subject_name") ?? "Unknown");
                            cmd.Parameters.AddWithValue("grade", grade);
                            cmd.Parameters.AddWithValue("sem", sem);
                            cmd.Parameters.AddWithValue("sy", sy);
                            cmd.Parameters.AddWithValue("yl", yearLevel ?? getVal("year_level") ?? "Unknown");
                            cmd.Parameters.AddWithValue("sec", section ?? getVal("section") ?? "Unknown");
                            cmd.Parameters.AddWithValue("fid", facultyEmail);
                            await cmd.ExecuteNonQueryAsync();
                            count++;
                        }
                    } else if (ext == ".xlsx") {
                        using var wb = new XLWorkbook(tempFile);
                        var ws = wb.Worksheet(1);
                        var headerRow = ws.FirstRowUsed();
                        var headerMap = new Dictionary<string, int>();
                        if (headerRow != null) {
                            foreach (var cell in headerRow.CellsUsed())
                                headerMap[cell.Value.ToString().Trim().ToLower().Replace(" ", "_")] = cell.Address.ColumnNumber;
                        }

                        foreach (var row in ws.RowsUsed().Skip(1)) {
                            var getVal = (string col) => headerMap.ContainsKey(col) ? row.Cell(headerMap[col]).Value.ToString().Trim() : null;
                            
                            var studentId = getVal("student_id") ?? getVal("student_no") ?? row.Cell(1).Value.ToString() ?? "";
                            var grade = getVal("grade") ?? getVal("final_grade") ?? row.Cell(2).Value.ToString() ?? "";
                            var hashedStudentId = HashIdentifier(studentId);
                            var subjectCode = getVal("subject_code") ?? "Unknown";
                            var sem = semester ?? getVal("semester") ?? "Unknown";
                            var sy = schoolYear ?? getVal("school_year") ?? "Unknown";
                            
                            // Idempotency check (WBSD 1.4.2 & 1.5.2)
                            using var cmdCheck = new NpgsqlCommand("SELECT COUNT(1) FROM bulk_grade_staging WHERE student_hash = @sh AND subject_code = @sub AND semester = @sem AND school_year = @sy", conn);
                            cmdCheck.Parameters.AddWithValue("sh", hashedStudentId);
                            cmdCheck.Parameters.AddWithValue("sub", subjectCode);
                            cmdCheck.Parameters.AddWithValue("sem", sem);
                            cmdCheck.Parameters.AddWithValue("sy", sy);
                            long exists = (long)(await cmdCheck.ExecuteScalarAsync() ?? 0);
                            if (exists > 0) continue;

                            using var cmd = new NpgsqlCommand(@"
                                INSERT INTO bulk_grade_staging (batch_id, student_hash, course, subject_code, subject_name, grade, semester, school_year, year_level, section, faculty_id, status)
                                VALUES (@bid, @sid, @course, @sub, @subn, @grade, @sem, @sy, @yl, @sec, @fid, 'PENDING_APPROVAL')", conn);
                            
                            cmd.Parameters.AddWithValue("bid", batchId);
                            cmd.Parameters.AddWithValue("sid", hashedStudentId);
                            cmd.Parameters.AddWithValue("course", getVal("course") ?? getVal("department") ?? "Unknown");
                            cmd.Parameters.AddWithValue("sub", subjectCode);
                            cmd.Parameters.AddWithValue("subn", getVal("subject_name") ?? "Unknown");
                            cmd.Parameters.AddWithValue("grade", grade);
                            cmd.Parameters.AddWithValue("sem", sem);
                            cmd.Parameters.AddWithValue("sy", sy);
                            cmd.Parameters.AddWithValue("yl", yearLevel ?? getVal("year_level") ?? "Unknown");
                            cmd.Parameters.AddWithValue("sec", section ?? getVal("section") ?? "Unknown");
                            cmd.Parameters.AddWithValue("fid", facultyEmail);
                            await cmd.ExecuteNonQueryAsync();
                            count++;
                        }
                    }

                    return Ok(new {
                        status = "Success",
                        message = $"{count} grades staged for approval with identity hashing. These will NOT appear on the ledger until finalized by the Registrar.",
                        batchId = batchId
                    });
                }
                finally
                {
                    if (System.IO.File.Exists(tempFile)) System.IO.File.Delete(tempFile);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Bulk upload error");
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost("approve-grades")]
        [Authorize(Roles = "department_admin,chairperson")]
        public async Task<IActionResult> ApproveGradesForDept([FromBody] ApproveGradesRequest request)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                int approvedCount = 0;

                foreach (var stagingId in request.StagingIds ?? new List<int>())
                {
                    using var cmd = new NpgsqlCommand(@"
                        UPDATE bulk_grade_staging SET status = 'APPROVED_BY_DEPT' 
                        WHERE staging_id = @id AND status = 'PENDING_APPROVAL'", conn);
                    cmd.Parameters.AddWithValue("id", stagingId);
                    approvedCount += await cmd.ExecuteNonQueryAsync();
                }

                return Ok(new { status = "Success", message = $"{approvedCount} grades approved by Department Admin. Ready for Registrar finalization.", approvedCount });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost("finalize-grades")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> FinalizeGradesAsRegistrar([FromBody] FinalizeGradesRequest request)
        {
            var registrarEmail = User.Identity?.Name;
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                int finalizedCount = 0;

                foreach (var stagingId in request.StagingIds ?? new List<int>())
                {
                    using var selectCmd = new NpgsqlCommand("SELECT * FROM bulk_grade_staging WHERE staging_id = @id", conn);
                    selectCmd.Parameters.AddWithValue("id", stagingId);
                    using var reader = await selectCmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync()) {
                        var record = new AcademicRecord {
                            Id = Guid.NewGuid().ToString(),
                            StudentHash = reader["student_hash"].ToString() ?? "",
                            Course = reader["course"].ToString() ?? "",
                            SubjectCode = reader["subject_code"].ToString() ?? "",
                            Grade = reader["grade"].ToString() ?? "",
                            Semester = reader["semester"].ToString() ?? "",
                            SchoolYear = reader["school_year"].ToString() ?? "",
                            YearLevel = reader["year_level"].ToString() ?? "",
                            Section = reader["section"].ToString() ?? "",
                            FacultyId = reader["faculty_id"].ToString() ?? "",
                            University = "PLV",
                            Date = DateTime.Now.ToString("yyyy-MM-dd"),
                            Status = "FINALIZED",
                            Version = 1
                        };
                        reader.Close();

                        await _blockchainService.SubmitGradeAsync(record, registrarEmail ?? "system");

                        using var deleteCmd = new NpgsqlCommand("DELETE FROM bulk_grade_staging WHERE staging_id = @id", conn);
                        deleteCmd.Parameters.AddWithValue("id", stagingId);
                        await deleteCmd.ExecuteNonQueryAsync();

                        using var auditCmd = new NpgsqlCommand(@"
                            INSERT INTO gradecorrectionlogs (recordid, oldgrade, newgrade, reasontext, approvedby, timestamp)
                            VALUES (@rid, 'STAGED', 'FINALIZED', 'Bulk Finalization to Ledger', @reg, CURRENT_TIMESTAMP)", conn);
                        auditCmd.Parameters.AddWithValue("rid", record.Id);
                        auditCmd.Parameters.AddWithValue("reg", registrarEmail ?? "system");
                        await auditCmd.ExecuteNonQueryAsync();

                        finalizedCount++;
                    } else {
                        reader.Close();
                    }
                }

                return Ok(new { status = "Success", message = $"{finalizedCount} grades officially committed to the blockchain ledger.", finalizedCount });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Finalization error");
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("staged")]
        public async Task<IActionResult> GetStagedGrades([FromQuery] string? status)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                var query = "SELECT * FROM bulk_grade_staging";
                if (!string.IsNullOrEmpty(status)) query += " WHERE status = @status";
                
                using var cmd = new NpgsqlCommand(query, conn);
                if (!string.IsNullOrEmpty(status)) cmd.Parameters.AddWithValue("status", status);
                
                var results = new List<object>();
                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync()) {
                    results.Add(new {
                        stagingId = reader["staging_id"],
                        batchId = reader["batch_id"],
                        studentHash = MaskHash(reader["student_hash"].ToString() ?? ""),
                        course = reader["course"],
                        subjectCode = reader["subject_code"],
                        grade = reader["grade"],
                        status = reader["status"],
                        yearLevel = reader["year_level"],
                        section = reader["section"],
                        facultyId = reader["faculty_id"],
                        semester = reader["semester"],
                        schoolYear = reader["school_year"]
                    });
                }
                return Ok(new { status = "Success", data = results });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost("bulk-faculty-sections-upload")]
        [Authorize(Roles = "registrar,department_admin")]
        [HttpPost("bulk-faculty-load")]
        [HttpPost("bulk-faculty-sections")]
        [HttpPost("bulk-faculty-load-csv")]
        [HttpPost("/api/bulk-faculty-load")]
        [HttpPost("/api/bulk-faculty-sections")]
        [HttpPost("/api/bulk-faculty-sections-upload")]
        [Authorize(Roles = "registrar,department_admin,chairperson,admin")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> BulkFacultySectionsUpload([FromForm] IFormFile file, [FromForm] string? department)
        {
            _logger.LogInformation("Bulk faculty sections upload initiated by: {User}", User.Identity?.Name);

            if (file == null || file.Length == 0)
                return BadRequest(new { status = "Error", message = "CSV file required." });

            var ext = Path.GetExtension(file.FileName).ToLower();
            if (ext != ".csv" && ext != ".xlsx")
                return BadRequest(new { status = "Error", message = "Only .csv and .xlsx files are supported." });

            var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ext);

            try
            {
                using (var fileStream = new FileStream(tempFile, FileMode.Create))
                    await file.CopyToAsync(fileStream);

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                int count = 0;
                var errors = new List<string>();

                if (ext == ".csv")
                {
                    using var reader = new StreamReader(tempFile);
                    var header = await reader.ReadLineAsync();
                    var headerFields = header == null
                        ? new List<string>()
                        : ParseCsvLine(header).Select(f => f?.Trim().ToLower().Replace(" ", "_") ?? "").ToList();

                    int lineNum = 1;
                    while (!reader.EndOfStream)
                    {
                        lineNum++;
                        var line = await reader.ReadLineAsync();
                        if (string.IsNullOrEmpty(line)) continue;

                        var parts = ParseCsvLine(line);
                        if (parts.Length < 2) continue;

                        try
                        {
                            var getVal = (string col) =>
                            {
                                var idx = headerFields?.IndexOf(col) ?? -1;
                                return (idx >= 0 && idx < parts.Length) ? parts[idx]?.Trim() : null;
                            };

                            var facultyEmail = getVal("faculty_email") ?? getVal("email") ?? getVal("faculty") ?? getVal("faculty_id") ?? getVal("instructor") ?? parts[0]?.Trim();
                            var subject = getVal("subject") ?? getVal("subject_code") ?? getVal("subject_name") ?? getVal("course_code") ?? (parts.Length > 1 ? parts[1]?.Trim() : "");
                            var section = getVal("section") ?? getVal("class_section") ?? getVal("section_name") ?? (parts.Length > 2 ? parts[2]?.Trim() : "");
                            var yearLevel = getVal("year_level") ?? getVal("year") ?? getVal("yearlevel") ?? (parts.Length > 3 ? parts[3]?.Trim() : "");
                            var dept = getVal("department") ?? getVal("dept") ?? getVal("course") ?? department ?? "";

                            if (string.IsNullOrWhiteSpace(facultyEmail) || string.IsNullOrWhiteSpace(subject))
                                throw new Exception("Faculty email and subject are required.");

                            // Verify faculty exists
                            using var checkCmd = new NpgsqlCommand(@"
                                SELECT u.id FROM Users u
                                LEFT JOIN FacultyProfiles fp ON fp.user_id = u.id
                                WHERE (LOWER(u.email) = LOWER(@identifier) 
                                    OR LOWER(u.username) = LOWER(@identifier) 
                                    OR LOWER(fp.full_name) = LOWER(@identifier)
                                    OR LOWER(u.email) = LOWER(@identifierWithDomain))
                                  AND u.role = 'faculty'
                                LIMIT 1", conn);
                            checkCmd.Parameters.AddWithValue("identifier", facultyEmail.Trim());
                            checkCmd.Parameters.AddWithValue("identifierWithDomain", facultyEmail.Contains("@") ? facultyEmail.Trim() : $"{facultyEmail.Trim()}@plv.edu.ph");
                            var facultyId = await checkCmd.ExecuteScalarAsync();

                            if (facultyId == null)
                                throw new Exception($"Faculty account {facultyEmail} not found.");

                            // Insert or update FacultySections
                            using var cmd = new NpgsqlCommand(@"
                                INSERT INTO FacultySections (user_id, department, subject, section, year_level)
                                VALUES (@uid, @dept, @subject, @section, @year)
                                ON CONFLICT (user_id, department, subject, section) DO NOTHING", conn);
                            cmd.Parameters.AddWithValue("uid", facultyId);
                            cmd.Parameters.AddWithValue("dept", string.IsNullOrWhiteSpace(dept) ? (object)DBNull.Value : dept);
                            cmd.Parameters.AddWithValue("subject", subject.Trim());
                            cmd.Parameters.AddWithValue("section", string.IsNullOrWhiteSpace(section) ? (object)DBNull.Value : section);
                            cmd.Parameters.AddWithValue("year", string.IsNullOrWhiteSpace(yearLevel) ? (object)DBNull.Value : yearLevel);
                            await cmd.ExecuteNonQueryAsync();
                            count++;
                        }
                        catch (Exception ex)
                        {
                            errors.Add($"Line {lineNum}: {ex.Message}");
                        }
                    }
                }
                else if (ext == ".xlsx")
                {
                    using var wb = new XLWorkbook(tempFile);
                    var ws = wb.Worksheet(1);
                    var headerRow = ws.FirstRowUsed();
                    var headerMap = new Dictionary<string, int>();
                    if (headerRow != null)
                    {
                        foreach (var cell in headerRow.CellsUsed())
                            headerMap[cell.Value.ToString().Trim().ToLower().Replace(" ", "_")] = cell.Address.ColumnNumber;
                    }

                    int rowNum = 1;
                    foreach (var row in ws.RowsUsed().Skip(1))
                    {
                        rowNum++;
                        try
                        {
                            var getVal = (string col) => headerMap.ContainsKey(col) ? row.Cell(headerMap[col]).Value.ToString().Trim() : null;

                            var facultyEmail = getVal("faculty_email") ?? getVal("email") ?? row.Cell(1).Value.ToString()?.Trim();
                            var subject = getVal("subject") ?? getVal("subject_code") ?? row.Cell(2).Value.ToString()?.Trim() ?? "";
                            var section = getVal("section") ?? getVal("class_section") ?? "";
                            var yearLevel = getVal("year_level") ?? getVal("year") ?? "";
                            var dept = getVal("department") ?? department ?? "";

                            if (string.IsNullOrWhiteSpace(facultyEmail) || string.IsNullOrWhiteSpace(subject))
                                throw new Exception("Faculty email and subject are required.");

                            using var checkCmd = new NpgsqlCommand(
                                "SELECT id FROM Users WHERE LOWER(email) = LOWER(@email) AND role = 'faculty'", conn);
                            checkCmd.Parameters.AddWithValue("email", facultyEmail.Trim());
                            var facultyId = await checkCmd.ExecuteScalarAsync();

                            if (facultyId == null)
                                throw new Exception($"Faculty account {facultyEmail} not found.");

                            using var cmd = new NpgsqlCommand(@"
                                INSERT INTO FacultySections (user_id, department, subject, section, year_level)
                                VALUES (@uid, @dept, @subject, @section, @year)
                                ON CONFLICT (user_id, department, subject, section) DO NOTHING", conn);
                            cmd.Parameters.AddWithValue("uid", facultyId);
                            cmd.Parameters.AddWithValue("dept", string.IsNullOrWhiteSpace(dept) ? (object)DBNull.Value : dept);
                            cmd.Parameters.AddWithValue("subject", subject.Trim());
                            cmd.Parameters.AddWithValue("section", string.IsNullOrWhiteSpace(section) ? (object)DBNull.Value : section);
                            cmd.Parameters.AddWithValue("year", string.IsNullOrWhiteSpace(yearLevel) ? (object)DBNull.Value : yearLevel);
                            await cmd.ExecuteNonQueryAsync();
                            count++;
                        }
                        catch (Exception ex)
                        {
                            errors.Add($"Row {rowNum}: {ex.Message}");
                        }
                    }
                }

                return Ok(new
                {
                    status = errors.Count == 0 ? "Success" : "Partial Success",
                    message = $"{count} faculty-section assignments loaded.",
                    processed = count,
                    errors = errors.Any() ? errors : null
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Bulk faculty sections upload error");
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
            finally
            {
                if (System.IO.File.Exists(tempFile)) System.IO.File.Delete(tempFile);
            }
        }

        [HttpPost("bulk-faculty-load-chairperson")]
        [Authorize(Roles = "department_admin,chairperson")]
        [HttpPost("assign-faculty-bulk")]
        [HttpPost("/api/assign-faculty-bulk")]
        [HttpPost("/api/chairperson/assign-faculty-bulk")]
        [HttpPost("/api/bulk-faculty-load-chairperson")]
        [Authorize(Roles = "department_admin,chairperson,registrar,admin")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> BulkFacultyLoadChairperson([FromForm] IFormFile file, [FromForm] string? department)
        {
            _logger.LogInformation("Chairperson bulk faculty load initiated by: {User}", User.Identity?.Name);

            if (file == null || file.Length == 0)
                return BadRequest(new { status = "Error", message = "CSV file required." });

            var ext = Path.GetExtension(file.FileName).ToLower();
            if (ext != ".csv" && ext != ".xlsx")
                return BadRequest(new { status = "Error", message = "Only .csv and .xlsx files are supported." });

            var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ext);

            try
            {
                using (var fileStream = new FileStream(tempFile, FileMode.Create))
                    await file.CopyToAsync(fileStream);

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                // Verify chairperson department authorization
                var userIdentifier = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                                     ?? User.FindFirst("email")?.Value
                                     ?? User.Identity?.Name ?? "";

                using var chairCmd = new NpgsqlCommand(@"
                    SELECT ap.department FROM Users u
                    JOIN AdminProfiles ap ON ap.user_id = u.id
                    WHERE (LOWER(u.email) = LOWER(@ident) OR LOWER(u.username) = LOWER(@ident))
                      AND (u.role IN ('department_admin', 'deptAdmin', 'chairperson', 'admin') OR u.role ILIKE '%chair%' OR u.role ILIKE '%dept%')
                    LIMIT 1", conn);
                chairCmd.Parameters.AddWithValue("ident", userIdentifier);
                var chairDept = await chairCmd.ExecuteScalarAsync() as string;

                if (string.IsNullOrWhiteSpace(chairDept))
                {
                    chairDept = User.FindFirst("department")?.Value ?? department;
                }

                if (string.IsNullOrWhiteSpace(chairDept) && !string.IsNullOrWhiteSpace(department))
                {
                    chairDept = department;
                }

                if (string.IsNullOrWhiteSpace(chairDept))
                {
                    using var anyDeptCmd = new NpgsqlCommand(@"
                        SELECT ap.department FROM AdminProfiles ap
                        JOIN Users u ON u.id = ap.user_id
                        WHERE LOWER(u.email) = LOWER(@ident) OR LOWER(u.username) = LOWER(@ident)
                        LIMIT 1", conn);
                    anyDeptCmd.Parameters.AddWithValue("ident", userIdentifier);
                    chairDept = await anyDeptCmd.ExecuteScalarAsync() as string;
                }

                if (string.IsNullOrWhiteSpace(chairDept))
                {
                    chairDept = "General";
                }

                int count = 0;
                var errors = new List<string>();

                if (ext == ".csv")
                {
                    using var reader = new StreamReader(tempFile);
                    var header = await reader.ReadLineAsync();
                    var headerFields = header == null
                        ? new List<string>()
                        : ParseCsvLine(header).Select(f => f?.Trim().ToLower().Replace(" ", "_") ?? "").ToList();

                    int lineNum = 1;
                    while (!reader.EndOfStream)
                    {
                        lineNum++;
                        var line = await reader.ReadLineAsync();
                        if (string.IsNullOrEmpty(line)) continue;

                        var parts = ParseCsvLine(line);
                        if (parts.Length < 2) continue;

                        try
                        {
                            var getVal = (string col) =>
                            {
                                var idx = headerFields?.IndexOf(col) ?? -1;
                                return (idx >= 0 && idx < parts.Length) ? parts[idx]?.Trim() : null;
                            };

                            var facultyEmail = getVal("faculty_email") ?? getVal("email") ?? getVal("faculty") ?? getVal("faculty_id") ?? getVal("instructor") ?? parts[0]?.Trim();
                            var subject = getVal("subject") ?? getVal("subject_code") ?? getVal("subject_name") ?? getVal("course_code") ?? (parts.Length > 1 ? parts[1]?.Trim() : "");
                            var section = getVal("section") ?? getVal("class_section") ?? getVal("section_name") ?? (parts.Length > 2 ? parts[2]?.Trim() : "");
                            var yearLevel = getVal("year_level") ?? getVal("year") ?? getVal("yearlevel") ?? (parts.Length > 3 ? parts[3]?.Trim() : "");
                            var deptToUse = string.IsNullOrWhiteSpace(department) ? chairDept : department;

                            if (string.IsNullOrWhiteSpace(facultyEmail) || string.IsNullOrWhiteSpace(subject))
                                throw new Exception("Faculty email and subject are required.");

                            using var checkCmd = new NpgsqlCommand(@"
                                SELECT u.id FROM Users u
                                LEFT JOIN FacultyProfiles fp ON fp.user_id = u.id
                                WHERE (LOWER(u.email) = LOWER(@identifier) 
                                    OR LOWER(u.username) = LOWER(@identifier) 
                                    OR LOWER(fp.full_name) = LOWER(@identifier)
                                    OR LOWER(u.email) = LOWER(@identifierWithDomain))
                                  AND u.role = 'faculty'
                                LIMIT 1", conn);
                            checkCmd.Parameters.AddWithValue("identifier", facultyEmail.Trim());
                            checkCmd.Parameters.AddWithValue("identifierWithDomain", facultyEmail.Contains("@") ? facultyEmail.Trim() : $"{facultyEmail.Trim()}@plv.edu.ph");
                            var facultyId = await checkCmd.ExecuteScalarAsync();

                            if (facultyId == null)
                                throw new Exception($"Faculty account {facultyEmail} not found.");

                            using var cmd = new NpgsqlCommand(@"
                                INSERT INTO FacultySections (user_id, department, subject, section, year_level)
                                VALUES (@uid, @dept, @subject, @section, @year)
                                ON CONFLICT (user_id, department, subject, section) DO NOTHING", conn);
                            cmd.Parameters.AddWithValue("uid", facultyId);
                            cmd.Parameters.AddWithValue("dept", string.IsNullOrWhiteSpace(deptToUse) ? (object)DBNull.Value : deptToUse);
                            cmd.Parameters.AddWithValue("subject", subject.Trim());
                            cmd.Parameters.AddWithValue("section", string.IsNullOrWhiteSpace(section) ? (object)DBNull.Value : section);
                            cmd.Parameters.AddWithValue("year", string.IsNullOrWhiteSpace(yearLevel) ? (object)DBNull.Value : yearLevel);
                            await cmd.ExecuteNonQueryAsync();
                            count++;
                        }
                        catch (Exception ex)
                        {
                            errors.Add($"Line {lineNum}: {ex.Message}");
                        }
                    }
                }
                else if (ext == ".xlsx")
                {
                    using var wb = new XLWorkbook(tempFile);
                    var ws = wb.Worksheet(1);
                    var headerRow = ws.FirstRowUsed();
                    var headerMap = new Dictionary<string, int>();
                    if (headerRow != null)
                    {
                        foreach (var cell in headerRow.CellsUsed())
                            headerMap[cell.Value.ToString().Trim().ToLower().Replace(" ", "_")] = cell.Address.ColumnNumber;
                    }

                    int rowNum = 1;
                    foreach (var row in ws.RowsUsed().Skip(1))
                    {
                        rowNum++;
                        try
                        {
                            var getVal = (string col) => headerMap.ContainsKey(col) ? row.Cell(headerMap[col]).Value.ToString().Trim() : null;

                            var facultyEmail = getVal("faculty_email") ?? getVal("email") ?? getVal("faculty") ?? getVal("faculty_id") ?? getVal("instructor") ?? row.Cell(1).Value.ToString()?.Trim();
                            var subject = getVal("subject") ?? getVal("subject_code") ?? getVal("subject_name") ?? getVal("course_code") ?? (row.Cell(2).Value.ToString()?.Trim() ?? "");
                            var section = getVal("section") ?? getVal("class_section") ?? getVal("section_name") ?? "";
                            var yearLevel = getVal("year_level") ?? getVal("year") ?? getVal("yearlevel") ?? "";
                            var deptToUse = string.IsNullOrWhiteSpace(department) ? chairDept : department;

                            if (string.IsNullOrWhiteSpace(facultyEmail) || string.IsNullOrWhiteSpace(subject))
                                throw new Exception("Faculty email and subject are required.");

                            using var checkCmd = new NpgsqlCommand(@"
                                SELECT u.id FROM Users u
                                LEFT JOIN FacultyProfiles fp ON fp.user_id = u.id
                                WHERE (LOWER(u.email) = LOWER(@identifier) 
                                    OR LOWER(u.username) = LOWER(@identifier) 
                                    OR LOWER(fp.full_name) = LOWER(@identifier)
                                    OR LOWER(u.email) = LOWER(@identifierWithDomain))
                                  AND u.role = 'faculty'
                                LIMIT 1", conn);
                            checkCmd.Parameters.AddWithValue("identifier", facultyEmail.Trim());
                            checkCmd.Parameters.AddWithValue("identifierWithDomain", facultyEmail.Contains("@") ? facultyEmail.Trim() : $"{facultyEmail.Trim()}@plv.edu.ph");
                            var facultyId = await checkCmd.ExecuteScalarAsync();

                            if (facultyId == null)
                                throw new Exception($"Faculty account {facultyEmail} not found.");

                            using var cmd = new NpgsqlCommand(@"
                                INSERT INTO FacultySections (user_id, department, subject, section, year_level)
                                VALUES (@uid, @dept, @subject, @section, @year)
                                ON CONFLICT (user_id, department, subject, section) DO NOTHING", conn);
                            cmd.Parameters.AddWithValue("uid", facultyId);
                            cmd.Parameters.AddWithValue("dept", string.IsNullOrWhiteSpace(deptToUse) ? (object)DBNull.Value : deptToUse);
                            cmd.Parameters.AddWithValue("subject", subject.Trim());
                            cmd.Parameters.AddWithValue("section", string.IsNullOrWhiteSpace(section) ? (object)DBNull.Value : section);
                            cmd.Parameters.AddWithValue("year", string.IsNullOrWhiteSpace(yearLevel) ? (object)DBNull.Value : yearLevel);
                            await cmd.ExecuteNonQueryAsync();
                            count++;
                        }
                        catch (Exception ex)
                        {
                            errors.Add($"Row {rowNum}: {ex.Message}");
                        }
                    }
                }

                return Ok(new
                {
                    status = errors.Count == 0 ? "Success" : "Partial Success",
                    message = $"{count} faculty-section assignments loaded by chairperson.",
                    processed = count,
                    errors = errors.Any() ? errors : null
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Chairperson bulk faculty load error");
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
            finally
            {
                if (System.IO.File.Exists(tempFile)) System.IO.File.Delete(tempFile);
            }
        }
    }

    public class ApproveGradesRequest
    {
        public List<int> StagingIds { get; set; } = new();
    }

    public class FinalizeGradesRequest
    {
        public List<int> StagingIds { get; set; } = new();
    }
}
