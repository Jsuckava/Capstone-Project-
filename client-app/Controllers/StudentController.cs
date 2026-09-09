using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using For_Testing_Only_Capstone.Models;
using System;
using System.Threading.Tasks;
using BlockGo.Models;
using BlockGo.Services;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Globalization;
using Npgsql;

namespace Client_app.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class StudentController : ControllerBase
    {
        private readonly RegistrarDbContext _context;
        private readonly IBlockchainService _blockchain;
        private readonly string _connectionString;
        private readonly ILogger<StudentController> _logger;

        public StudentController(RegistrarDbContext context, IBlockchainService blockchain, IConfiguration configuration, ILogger<StudentController> logger)
        {
            _context = context;
            _blockchain = blockchain;
            _logger = logger;
            _connectionString = configuration.GetConnectionString("MasterConnection")
                ?? configuration.GetConnectionString("PostgresConnection")
                ?? throw new InvalidOperationException("A PostgreSQL connection is required.");
        }

        [HttpGet("profile")]
        [Authorize(Roles = "student")]
        public async Task<IActionResult> GetProfile()
        {
            var email = User.Identity?.Name;
            if (string.IsNullOrEmpty(email)) return Unauthorized();

            try
            {
                using var connection = _context.Database.GetDbConnection();
                await connection.OpenAsync();
                using var command = connection.CreateCommand();

                command.CommandText = @"
                    SELECT phone, sex, middle_name 
                    FROM studentprofiles 
                    WHERE user_id = (SELECT id FROM users WHERE email = @email)";

                var pEmail = command.CreateParameter(); pEmail.ParameterName = "@email"; pEmail.Value = email; command.Parameters.Add(pEmail);

                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    return Ok(new
                    {
                        phone = reader.IsDBNull(0) ? "" : reader.GetString(0),
                        sex = reader.IsDBNull(1) ? "" : reader.GetString(1),
                        middleName = reader.IsDBNull(2) ? "" : reader.GetString(2)
                    });
                }
                return NotFound(new { message = "Profile not found." });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Profile Fetch Error]: {ex}");
                return StatusCode(500, new { message = "Database error fetching profile.", error = ex.Message });
            }
        }

        [HttpPut("profile")]
        [Authorize(Roles = "student")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
        {
            var email = User.Identity?.Name;
            // If the user is an admin/faculty, they might be passing a specific student email
            // (Need to extend UpdateProfileRequest to support this if we want admins to edit others)
            if (string.IsNullOrEmpty(email)) return Unauthorized();

            try
            {
                using var connection = _context.Database.GetDbConnection();
                await connection.OpenAsync();
                using var command = connection.CreateCommand();

                command.CommandText = @"
                    UPDATE studentprofiles 
                    SET phone = @phone, sex = @sex, middle_name = @middleName
                    WHERE user_id = (SELECT id FROM users WHERE email = @email)";

                var pPhone = command.CreateParameter(); pPhone.ParameterName = "@phone"; pPhone.Value = string.IsNullOrEmpty(request.Phone) ? DBNull.Value : request.Phone; command.Parameters.Add(pPhone);
                var pSex = command.CreateParameter(); pSex.ParameterName = "@sex"; pSex.Value = string.IsNullOrEmpty(request.Sex) ? DBNull.Value : request.Sex; command.Parameters.Add(pSex);
                var pMiddleName = command.CreateParameter(); pMiddleName.ParameterName = "@middleName"; pMiddleName.Value = string.IsNullOrEmpty(request.MiddleName) ? DBNull.Value : request.MiddleName; command.Parameters.Add(pMiddleName);
                var pEmail = command.CreateParameter(); pEmail.ParameterName = "@email"; pEmail.Value = email; command.Parameters.Add(pEmail);

                int rowsAffected = await command.ExecuteNonQueryAsync();

                if (rowsAffected == 0) return NotFound(new { message = "Profile not found." });

                return Ok(new { message = "Profile updated successfully." });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Profile Update Error]: {ex}");
                return StatusCode(500, new { message = "Database error updating profile.", error = ex.Message });
            }
        }

        [HttpGet("grades")]
        [Authorize(Roles = "student")]
        public async Task<IActionResult> GetHistoricalGrades(CancellationToken cancellationToken)
        {
            var email = User.Identity?.Name;
            if (string.IsNullOrWhiteSpace(email)) return Unauthorized();

            try
            {
                var responseJson = await _blockchain.GetAllGradesAsync(email);
                using var responseDocument = JsonDocument.Parse(responseJson);
                var data = responseDocument.RootElement.TryGetProperty("data", out var dataElement)
                    ? dataElement
                    : responseDocument.RootElement;
                var records = JsonSerializer.Deserialize<List<AcademicRecord>>(
                    data.GetRawText(),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new List<AcademicRecord>();

                records = records.Where(record =>
                    string.Equals(record.StudentHash, email, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(record.Status, "Finalized", StringComparison.OrdinalIgnoreCase)).ToList();

                var facultyNames = await LoadFacultyNamesAsync(records.Select(record => record.FacultyId), cancellationToken);
                var subjectMetadata = await LoadSubjectMetadataAsync(email, cancellationToken);
                var grades = new List<object>();
                foreach (var record in records)
                {
                    var yearLevel = ParseYearLevel(record.YearLevel, record.Section);
                    var subjectTitle = !string.IsNullOrWhiteSpace(record.SubjectTitle)
                        ? record.SubjectTitle
                        : subjectMetadata.TryGetValue(record.SubjectCode, out var subject) ? subject.Title : record.SubjectCode;
                    var units = record.Units > 0
                        ? record.Units
                        : subjectMetadata.TryGetValue(record.SubjectCode, out subject) ? subject.Units : 0;
                    var professor = !string.IsNullOrWhiteSpace(record.ProfessorName)
                        ? record.ProfessorName
                        : facultyNames.TryGetValue(record.FacultyId, out var name) ? name : record.FacultyId;
                    var terms = ParseGradeTerms(record.Grade, record.Term);

                    foreach (var term in terms)
                    {
                        grades.Add(new
                        {
                            recordId = record.Id,
                            studentId = string.IsNullOrWhiteSpace(record.StudentId) ? record.StudentNo : record.StudentId,
                            subjectCode = record.SubjectCode,
                            subjectTitle,
                            professor,
                            facultyId = record.FacultyId,
                            units,
                            yearLevel,
                            semester = record.Semester,
                            schoolYear = record.SchoolYear,
                            term = term.Name,
                            grade = term.Grade,
                            finalAverage = term.FinalAverage,
                            status = record.Status,
                            transactionId = record.TransactionId,
                            transactionHash = string.IsNullOrWhiteSpace(record.TransactionHash) ? record.TransactionId : record.TransactionHash,
                            timestamp = record.Timestamp,
                            date = record.Date
                        });
                    }
                }

                var orderedGrades = grades.OrderBy(item => JsonSerializer.Serialize(item)).ToArray();
                return Ok(new
                {
                    status = "Success",
                    data = orderedGrades,
                    message = orderedGrades.Length == 0 ? "There are currently no grade records available." : null
                });
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Blockchain grade retrieval failed for student {StudentEmail}", email);
                return StatusCode(StatusCodes.Status502BadGateway, new
                {
                    status = "Error",
                    message = "Unable to retrieve grade records from the blockchain. Please try again later."
                });
            }
        }

        [HttpGet("blockchain-transactions")]
        [Authorize(Roles = "student")]
        public async Task<IActionResult> GetBlockchainTransactions()
        {
            var email = User.Identity?.Name;
            if (string.IsNullOrWhiteSpace(email)) return Unauthorized();

            var responseJson = await _blockchain.GetStudentTransactionsAsync(email);
            using var responseDocument = JsonDocument.Parse(responseJson);
            var data = responseDocument.RootElement.TryGetProperty("data", out var dataElement)
                ? dataElement
                : responseDocument.RootElement;
            var safeTransactions = new List<object>();
            if (data.ValueKind == JsonValueKind.Array)
            {
                foreach (var transaction in data.EnumerateArray())
                {
                    if (!transaction.TryGetProperty("record", out var recordElement)) continue;
                    var record = JsonSerializer.Deserialize<AcademicRecord>(recordElement.GetRawText(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (record is null || !string.Equals(record.StudentHash, email, StringComparison.OrdinalIgnoreCase)) continue;

                    var transactionId = GetJsonString(transaction, "transaction_id");
                    safeTransactions.Add(new
                    {
                        transactionId,
                        transactionHash = GetJsonString(transaction, "transaction_hash", transactionId),
                        transactionType = GetJsonString(transaction, "transaction_type", "GRADE_UPDATED"),
                        studentId = string.IsNullOrWhiteSpace(record.StudentId) ? record.StudentNo : record.StudentId,
                        subjectCode = record.SubjectCode,
                        subjectTitle = record.SubjectTitle,
                        professor = string.IsNullOrWhiteSpace(record.ProfessorName) ? record.FacultyId : record.ProfessorName,
                        facultyId = record.FacultyId,
                        program = string.IsNullOrWhiteSpace(record.Program) ? record.Course : record.Program,
                        section = record.Section,
                        yearLevel = ParseYearLevel(record.YearLevel, record.Section),
                        semester = record.Semester,
                        schoolYear = record.SchoolYear,
                        term = string.IsNullOrWhiteSpace(record.Term) ? InferTerm(record.Grade) : record.Term,
                        grade = GetDisplayGrade(record.Grade, record.Term),
                        status = record.Status,
                        timestamp = NormalizeTransactionTimestamp(GetJsonString(transaction, "timestamp", record.Timestamp))
                    });
                }
            }
            return Ok(new { status = "Success", data = safeTransactions });
        }

        private async Task<Dictionary<string, string>> LoadFacultyNamesAsync(IEnumerable<string> facultyIds, CancellationToken cancellationToken)
        {
            var ids = facultyIds.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ids.Length == 0) return result;
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT u.email, COALESCE(fp.full_name, ap.full_name, u.email)
                FROM users u
                LEFT JOIN facultyprofiles fp ON fp.user_id = u.id
                LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                WHERE u.email = ANY(@ids);";
            var parameter = command.CreateParameter(); parameter.ParameterName = "@ids"; parameter.Value = ids; command.Parameters.Add(parameter);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) result[reader.GetString(0)] = reader.GetString(1);
            return result;
        }

        private async Task<Dictionary<string, (string Title, decimal Units)>> LoadSubjectMetadataAsync(string email, CancellationToken cancellationToken)
        {
            var result = new Dictionary<string, (string Title, decimal Units)>(StringComparer.OrdinalIgnoreCase);
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT cs.subject_code, cs.subject_title, cs.units
                FROM users u
                JOIN studentprofiles sp ON sp.user_id = u.id
                LEFT JOIN LATERAL (
                    SELECT se.curriculum_id
                    FROM student_enrollments se
                    WHERE se.student_user_id = u.id
                    ORDER BY se.updated_at DESC, se.enrollment_id DESC
                    LIMIT 1
                ) enrollment ON TRUE
                JOIN curriculums c
                  ON c.curriculum_id = COALESCE(enrollment.curriculum_id, sp.curriculum_id)
                 AND c.status IN ('PUBLISHED', 'ARCHIVED')
                JOIN curriculum_subjects cs ON cs.curriculum_id = c.curriculum_id
                WHERE LOWER(u.email) = LOWER(@email);";
            var parameter = command.CreateParameter(); parameter.ParameterName = "@email"; parameter.Value = email; command.Parameters.Add(parameter);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) result[reader.GetString(0)] = (reader.GetString(1), reader.GetDecimal(2));
            return result;
        }

        private static IReadOnlyCollection<(string Name, string Grade, string FinalAverage)> ParseGradeTerms(string rawGrade, string explicitTerm)
        {
            var terms = new List<(string Name, string Grade, string FinalAverage)>();
            if (!string.IsNullOrWhiteSpace(rawGrade) && rawGrade.TrimStart().StartsWith("{"))
            {
                try
                {
                    using var document = JsonDocument.Parse(rawGrade);
                    var finalAverage = GetJsonString(document.RootElement, "finalAverage");
                    var midterm = GetJsonString(document.RootElement, "midterm");
                    var finals = GetJsonString(document.RootElement, "finals");
                    if (!string.IsNullOrWhiteSpace(midterm)) terms.Add(("midterm", midterm, finalAverage));
                    if (!string.IsNullOrWhiteSpace(finals)) terms.Add(("finals", finals, finalAverage));
                }
                catch { }
            }
            if (terms.Count == 0) terms.Add((string.IsNullOrWhiteSpace(explicitTerm) ? "finals" : explicitTerm.ToLowerInvariant(), rawGrade, rawGrade));
            return terms;
        }

        private static string GetDisplayGrade(string rawGrade, string explicitTerm)
        {
            var term = string.IsNullOrWhiteSpace(explicitTerm) ? InferTerm(rawGrade) : explicitTerm;
            return ParseGradeTerms(rawGrade, term).FirstOrDefault(value => string.Equals(value.Name, term, StringComparison.OrdinalIgnoreCase)).Grade
                ?? ParseGradeTerms(rawGrade, term).LastOrDefault().Grade
                ?? rawGrade;
        }

        private static string InferTerm(string rawGrade) => ParseGradeTerms(rawGrade, "midterm").Any(value => value.Name == "finals") ? "finals" : "midterm";

        private static string NormalizeTransactionTimestamp(string rawTimestamp)
        {
            if (string.IsNullOrWhiteSpace(rawTimestamp)) return "";

            var fabricTimestamp = Regex.Match(
                rawTimestamp,
                @"^seconds:\s*(-?\d+)\s+nanos:\s*(\d+)\s*$",
                RegexOptions.IgnoreCase);

            if (fabricTimestamp.Success &&
                long.TryParse(fabricTimestamp.Groups[1].Value, out var seconds) &&
                long.TryParse(fabricTimestamp.Groups[2].Value, out var nanoseconds))
            {
                try
                {
                    return DateTimeOffset
                        .FromUnixTimeSeconds(seconds)
                        .AddTicks(nanoseconds / 100)
                        .ToString("O", CultureInfo.InvariantCulture);
                }
                catch (ArgumentOutOfRangeException)
                {
                    return rawTimestamp;
                }
            }

            if (DateTimeOffset.TryParse(
                rawTimestamp,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsedTimestamp))
            {
                return parsedTimestamp.ToString("O", CultureInfo.InvariantCulture);
            }

            return rawTimestamp;
        }

        private static int ParseYearLevel(string? value, string? section)
        {
            var match = Regex.Match($"{value} {section}", @"\b([1-4])(?:st|nd|rd|th)?\b", RegexOptions.IgnoreCase);
            return match.Success && int.TryParse(match.Groups[1].Value, out var year) ? year : 0;
        }

        private static string GetJsonString(JsonElement element, string property, string fallback = "")
        {
            if (!element.TryGetProperty(property, out var value) || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) return fallback;
            return value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : value.ToString();
        }
    }

    public class UpdateProfileRequest
    {
        public string? Phone { get; set; }
        public string? Sex { get; set; }
        public string? MiddleName { get; set; }
    }
}
