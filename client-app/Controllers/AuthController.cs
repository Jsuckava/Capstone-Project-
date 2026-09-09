using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.SignalR;
using Client_app.Services;
using Npgsql;
using Client_app.Models;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Mail;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Security.Cryptography;
using ClosedXML.Excel;


namespace Client_app.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private const string EmailLogoContentId = "plv-logo";
        private readonly string _connectionString;
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<AuthController> _logger;
        private readonly IHubContext<ChatHub> _chatHubContext;
        private readonly IAuditLogService _auditLog;
        private static readonly object SchemaInitializationLock = new();
        private static bool _schemaInitialized;
        private static readonly SemaphoreSlim SharedStateSchemaLock = new(1, 1);
        private static bool _sharedStateSchemaInitialized;

        public AuthController(IConfiguration configuration, IMemoryCache memoryCache, IEmailService emailService, IHttpClientFactory httpClientFactory, ILogger<AuthController> logger, IHubContext<ChatHub> chatHubContext, IAuditLogService auditLog)
        {
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? throw new InvalidOperationException("PostgreSQL connection string 'PostgresConnection' not found.");
            _cache = memoryCache;
            _configuration = configuration;
            _emailService = emailService;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _chatHubContext = chatHubContext;
            _auditLog = auditLog;

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
                    CREATE TABLE IF NOT EXISTS AcademicSections (
                        id SERIAL PRIMARY KEY,
                        department VARCHAR(255) NOT NULL,
                        year_level INT NOT NULL,
                        section_num INT NOT NULL,
                        UNIQUE(department, year_level, section_num)
                    );
                    
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='facultysections' AND column_name='subject') THEN
                            ALTER TABLE facultysections ADD COLUMN subject VARCHAR(100);
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='facultyprofiles' AND column_name='faculty_type') THEN
                            ALTER TABLE facultyprofiles ADD COLUMN faculty_type VARCHAR(20);
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='studentprofiles' AND column_name='middle_name') THEN
                            ALTER TABLE studentprofiles ADD COLUMN middle_name VARCHAR(100);
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='studentprofiles' AND column_name='phone') THEN
                            ALTER TABLE studentprofiles ADD COLUMN phone VARCHAR(50);
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='studentprofiles' AND column_name='address') THEN
                            ALTER TABLE studentprofiles ADD COLUMN address TEXT;
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='studentprofiles' AND column_name='student_email') THEN
                            ALTER TABLE studentprofiles ADD COLUMN student_email VARCHAR(255);
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='studentprofiles' AND column_name='batch_year') THEN
                            ALTER TABLE studentprofiles ADD COLUMN batch_year INTEGER;
                        END IF;
                    END $$;

                    ALTER TABLE IF EXISTS student_enrollments ADD COLUMN IF NOT EXISTS batch_year INTEGER;

                    CREATE TABLE IF NOT EXISTS student_id_sequences (
                        enrollment_year INTEGER PRIMARY KEY CHECK (enrollment_year BETWEEN 2000 AND 9999),
                        last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );

                    DO $$
                    BEGIN
                        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='gradecorrectionlogs') THEN
                            ALTER TABLE gradecorrectionlogs
                                ALTER COLUMN oldgrade TYPE TEXT,
                                ALTER COLUMN newgrade TYPE TEXT;
                        END IF;
                    END $$;

                    CREATE TABLE IF NOT EXISTS shared_client_state (
                        key VARCHAR(120) PRIMARY KEY,
                        value JSONB NOT NULL,
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_by VARCHAR(255)
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_faculty_section ON facultysections(user_id, department, section, subject);
                ", conn);
                    cmd.ExecuteNonQuery();
                    System.Threading.Volatile.Write(ref _sharedStateSchemaInitialized, true);
                    System.Threading.Volatile.Write(ref _schemaInitialized, true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Database compatibility schema initialization was deferred.");
                }
            }
        }

        private Task NotifyAcademicDataChangedAsync(string reason, string? department = null, string? actor = null)
        {
            return _chatHubContext.Clients.All.SendAsync("AcademicDataChanged", new
            {
                Reason = reason,
                Department = department,
                Actor = actor,
                ChangedAt = DateTime.UtcNow
            });
        }

        private async Task SafeNotifyAcademicDataChangedAsync(string reason, string? department = null, string? actor = null)
        {
            try
            {
                await NotifyAcademicDataChangedAsync(reason, department, actor);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Academic data change notification failed for reason {Reason}.", reason);
            }
        }

        private async Task SafeInsertAuthAuditLogAsync(
            NpgsqlConnection conn,
            string recordId,
            string? oldValue,
            string? newValue,
            string reason,
            string? approvedBy)
        {
            try
            {
                using var auditCmd = new NpgsqlCommand(@"
                    INSERT INTO gradecorrectionlogs (recordid, oldgrade, newgrade, reasontext, approvedby, timestamp)
                    VALUES (@recordId, @oldValue, @newValue, @reason, @approvedBy, CURRENT_TIMESTAMP)", conn);
                auditCmd.Parameters.AddWithValue("recordId", recordId);
                auditCmd.Parameters.AddWithValue("oldValue", (object?)oldValue ?? DBNull.Value);
                auditCmd.Parameters.AddWithValue("newValue", (object?)newValue ?? DBNull.Value);
                auditCmd.Parameters.AddWithValue("reason", reason);
                auditCmd.Parameters.AddWithValue("approvedBy", (object?)(approvedBy ?? "Admin") ?? DBNull.Value);
                await auditCmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Auth revoke audit log insert failed for record {RecordId}.", recordId);
            }
        }

        private static string NormalizeSystemRole(string? role)
        {
            var normalized = (role ?? "student").Trim().ToLowerInvariant().Replace(" ", "_").Replace("-", "_");
            return normalized switch
            {
                "dept_admin" or "deptadmin" or "departmentadmin" or "department" or "admin" or "departmentmsp" or "chairperson" => "department_admin",
                "facultymsp" => "faculty",
                "registrarmsp" => "registrar",
                _ => normalized
            };
        }

        private async Task<bool> CanManageAcademicProgramAsync(
            NpgsqlConnection connection,
            string? department,
            CancellationToken cancellationToken = default)
        {
            if (User.IsInRole("registrar")) return true;
            if (!User.IsInRole("department_admin") || string.IsNullOrWhiteSpace(department)) return false;

            var actorEmail = User.Identity?.Name?.Trim();
            if (string.IsNullOrWhiteSpace(actorEmail)) return false;

            await using var command = new NpgsqlCommand(@"
                SELECT 1
                FROM users u
                JOIN adminprofiles ap ON ap.user_id = u.id
                JOIN academic_programs p
                  ON LOWER(ap.department) IN (LOWER(p.program_code), LOWER(p.program_name))
                WHERE LOWER(u.email) = LOWER(@actorEmail)
                  AND LOWER(@department) IN (LOWER(p.program_code), LOWER(p.program_name))
                  AND p.is_active = TRUE
                LIMIT 1;", connection);
            command.Parameters.AddWithValue("actorEmail", actorEmail);
            command.Parameters.AddWithValue("department", department.Trim());
            return await command.ExecuteScalarAsync(cancellationToken) is not null;
        }

        private static string CurrentSchoolYear()
        {
            var now = DateTime.UtcNow;
            var startYear = now.Month >= 6 ? now.Year : now.Year - 1;
            return $"{startYear}-{startYear + 1}";
        }

        private static string CurrentSemester() => DateTime.UtcNow.Month >= 6 ? "FIRST" : "SECOND";

        private static string NormalizeSchoolYear(string? value)
        {
            var normalized = (value ?? "").Trim();
            if (string.IsNullOrWhiteSpace(normalized)) return CurrentSchoolYear();
            var match = System.Text.RegularExpressions.Regex.Match(normalized, @"^(\d{4})\s*[-/]\s*(\d{4})$");
            if (!match.Success || int.Parse(match.Groups[2].Value) != int.Parse(match.Groups[1].Value) + 1)
                throw new ArgumentException("School year must use YYYY-YYYY with consecutive years.");
            return $"{match.Groups[1].Value}-{match.Groups[2].Value}";
        }

        private static string NormalizeEnrollmentSemester(string? value)
        {
            var normalized = (value ?? "").Trim().ToLowerInvariant().Replace("_", " ").Replace("-", " ");
            return normalized switch
            {
                "" => CurrentSemester(),
                "first" or "1" or "1st" or "first semester" or "1st semester" => "FIRST",
                "second" or "2" or "2nd" or "second semester" or "2nd semester" => "SECOND",
                "midyear" or "mid year" or "summer" => "MIDYEAR",
                _ => throw new ArgumentException("Semester must be First, Second, or Midyear.")
            };
        }

        private static short NormalizeYearLevel(string? value, string? section = null)
        {
            var candidate = (value ?? "").Trim();
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                var explicitMatch = System.Text.RegularExpressions.Regex.Match(candidate, @"^([1-4])(?:st|nd|rd|th)?(?:\s+year)?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (!explicitMatch.Success) throw new ArgumentException("Year level must be from 1 to 4.");
                return short.Parse(explicitMatch.Groups[1].Value);
            }

            var sectionMatch = System.Text.RegularExpressions.Regex.Match((section ?? "").Trim(), @"^([1-4])\s*-");
            return sectionMatch.Success ? short.Parse(sectionMatch.Groups[1].Value) : (short)1;
        }

        private static string NormalizeEnrollmentSection(string? value, short yearLevel)
        {
            var match = System.Text.RegularExpressions.Regex.Match((value ?? "").Trim(), @"^([1-4])\s*-\s*(\d+)$");
            if (!match.Success || !int.TryParse(match.Groups[2].Value, out var sectionNumber) || sectionNumber < 1)
                throw new ArgumentException("Section must use the year-section format, for example 2-1.");
            if (short.Parse(match.Groups[1].Value) != yearLevel)
                throw new ArgumentException("Section year must match the selected year level.");
            return $"{yearLevel}-{sectionNumber}";
        }

        private static int? SectionNumberFrom(string? section)
        {
            var match = System.Text.RegularExpressions.Regex.Match((section ?? "").Trim(), @"(\d+)\s*$");
            return match.Success && int.TryParse(match.Groups[1].Value, out var number) && number > 0 ? number : null;
        }

        private static async Task<(int Id, string Code, string Name)> ResolveEnrollmentProgramAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction? transaction,
            string program,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(program) || string.Equals(program.Trim(), "Unassigned", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("A valid academic program is required for enrollment.");

            await using var command = new NpgsqlCommand(@"
                SELECT program_id, program_code, program_name
                FROM academic_programs
                WHERE is_active = TRUE
                  AND (LOWER(program_code) = LOWER(@program) OR LOWER(program_name) = LOWER(@program))
                LIMIT 1;", connection, transaction);
            command.Parameters.AddWithValue("program", program.Trim());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                throw new ArgumentException("The selected academic program does not exist or is inactive.");
            return (reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
        }

        private static async Task<long?> ResolveEnrollmentCurriculumAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction? transaction,
            int programId,
            long? curriculumId,
            string? curriculumVersion,
            CancellationToken cancellationToken = default)
        {
            var hasRequestedVersion = !string.IsNullOrWhiteSpace(curriculumVersion);
            await using var command = new NpgsqlCommand(@"
                SELECT curriculum_id
                FROM curriculums
                WHERE program_id = @programId AND status = 'PUBLISHED'
                  AND (@curriculumId IS NULL OR curriculum_id = @curriculumId)
                  AND (@version IS NULL OR LOWER(curriculum_version) = LOWER(@version) OR LOWER(curriculum_code) = LOWER(@version))
                ORDER BY published_at DESC NULLS LAST, curriculum_id DESC
                LIMIT 1;", connection, transaction);
            command.Parameters.AddWithValue("programId", programId);
            command.Parameters.Add("curriculumId", NpgsqlTypes.NpgsqlDbType.Bigint).Value =
                (object?)curriculumId ?? DBNull.Value;
            command.Parameters.Add("version", NpgsqlTypes.NpgsqlDbType.Text).Value =
                hasRequestedVersion ? curriculumVersion!.Trim() : DBNull.Value;
            var result = await command.ExecuteScalarAsync(cancellationToken);
            if (result is null && (curriculumId.HasValue || hasRequestedVersion))
                throw new ArgumentException("The selected curriculum is not published or does not belong to the academic program.");
            return result is null ? null : Convert.ToInt64(result);
        }

        private static async Task<int?> EnsureEnrollmentSectionAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            string programName,
            short yearLevel,
            string? section,
            CancellationToken cancellationToken = default)
        {
            var sectionNumber = SectionNumberFrom(section);
            if (!sectionNumber.HasValue) return null;
            await using var command = new NpgsqlCommand(@"
                INSERT INTO academicsections (department, year_level, section_num)
                VALUES (@department, @yearLevel, @sectionNumber)
                ON CONFLICT (department, year_level, section_num)
                DO UPDATE SET department = EXCLUDED.department
                RETURNING id;", connection, transaction);
            command.Parameters.AddWithValue("department", programName);
            command.Parameters.AddWithValue("yearLevel", (int)yearLevel);
            command.Parameters.AddWithValue("sectionNumber", sectionNumber.Value);
            return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
        }

        private static async Task<string> AllocateStudentNumberAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, int year)
        {
            var prefix = (year % 100).ToString("00");
            await using var command = new NpgsqlCommand(@"
                INSERT INTO student_id_sequences (enrollment_year, last_sequence)
                SELECT @year, COALESCE(MAX(RIGHT(student_no, 4)::int), 0) + 1
                FROM studentprofiles WHERE student_no ~ @pattern
                ON CONFLICT (enrollment_year) DO UPDATE
                SET last_sequence = GREATEST(student_id_sequences.last_sequence + 1, EXCLUDED.last_sequence),
                    updated_at = CURRENT_TIMESTAMP
                RETURNING last_sequence;", connection, transaction);
            command.Parameters.AddWithValue("year", year);
            command.Parameters.AddWithValue("pattern", $"^{prefix}-[0-9]{{4}}$");
            var sequence = Convert.ToInt32(await command.ExecuteScalarAsync());
            return $"{prefix}-{sequence:0000}";
        }

        private static async Task UpsertStudentEnrollmentAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            int userId,
            string studentNo,
            int programId,
            long? curriculumId,
            int? academicSectionId,
            string schoolYear,
            string semester,
            short yearLevel,
            string? section,
            string actorEmail,
            CancellationToken cancellationToken = default)
        {
            await using var command = new NpgsqlCommand(@"
                INSERT INTO student_enrollments
                    (student_user_id, student_no, program_id, curriculum_id, academic_section_id,
                     school_year, semester, year_level, section, status, enrolled_by)
                VALUES
                    (@userId, @studentNo, @programId, @curriculumId, @academicSectionId,
                     @schoolYear, @semester, @yearLevel, @section, 'ENROLLED',
                     (SELECT id FROM users WHERE LOWER(email) = LOWER(@actorEmail) LIMIT 1))
                ON CONFLICT (student_user_id, school_year, semester)
                DO UPDATE SET student_no = EXCLUDED.student_no,
                              program_id = EXCLUDED.program_id,
                              curriculum_id = EXCLUDED.curriculum_id,
                              academic_section_id = CASE
                                  WHEN student_enrollments.program_id = EXCLUDED.program_id
                                   AND student_enrollments.year_level = EXCLUDED.year_level
                                  THEN COALESCE(EXCLUDED.academic_section_id, student_enrollments.academic_section_id)
                                  ELSE EXCLUDED.academic_section_id END,
                              year_level = EXCLUDED.year_level,
                              section = CASE
                                  WHEN student_enrollments.program_id = EXCLUDED.program_id
                                   AND student_enrollments.year_level = EXCLUDED.year_level
                                  THEN COALESCE(EXCLUDED.section, student_enrollments.section)
                                  ELSE EXCLUDED.section END,
                              status = 'ENROLLED',
                              enrolled_by = EXCLUDED.enrolled_by,
                              updated_at = CURRENT_TIMESTAMP;

                UPDATE studentprofiles sp
                SET section = latest.section, department = p.program_name,
                    year_level = latest.year_level::text, curriculum_id = latest.curriculum_id,
                    assignment_status = CASE latest.status WHEN 'ENROLLED' THEN 'Enrolled' ELSE latest.status END
                FROM student_enrollments latest JOIN academic_programs p ON p.program_id = latest.program_id
                WHERE sp.user_id = @userId AND latest.enrollment_id = (
                    SELECT e.enrollment_id FROM student_enrollments e WHERE e.student_user_id = @userId
                    ORDER BY e.school_year DESC,
                        CASE e.semester WHEN 'MIDYEAR' THEN 3 WHEN 'SECOND' THEN 2 ELSE 1 END DESC
                    LIMIT 1);", connection, transaction);
            command.Parameters.AddWithValue("userId", userId);
            command.Parameters.AddWithValue("studentNo", studentNo);
            command.Parameters.AddWithValue("programId", programId);
            command.Parameters.AddWithValue("curriculumId", (object?)curriculumId ?? DBNull.Value);
            command.Parameters.AddWithValue("academicSectionId", (object?)academicSectionId ?? DBNull.Value);
            command.Parameters.AddWithValue("schoolYear", schoolYear);
            command.Parameters.AddWithValue("semester", semester);
            command.Parameters.AddWithValue("yearLevel", yearLevel);
            command.Parameters.AddWithValue("section", string.IsNullOrWhiteSpace(section) ? DBNull.Value : section.Trim());
            command.Parameters.AddWithValue("actorEmail", actorEmail);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        [HttpPost("send-verification")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> SendVerificationCode([FromBody] VerificationRequest request)
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return StatusCode(StatusCodes.Status410Gone, new { status = "Error", message = "Public registration has been disabled. Accounts are created by authorized administrators." });
            }
            if (string.IsNullOrEmpty(request.Email))
            {
                return BadRequest(new { status = "Error", message = "Email is required." });
            }

            try
            {
                var normalizedEmail = request.Email.Trim().ToLower();

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using (var checkCmd = new NpgsqlCommand("SELECT COUNT(1) FROM Users WHERE email = @email", conn))
                {
                    checkCmd.Parameters.AddWithValue("email", normalizedEmail);
                    long userCount = (long)(await checkCmd.ExecuteScalarAsync() ?? 0);
                    if (userCount > 0)
                    {
                        return BadRequest(new { status = "Error", message = "An account with this email already exists or is currently pending approval." });
                    }
                }

                var verificationCode = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
                var cacheKey = $"verification_{normalizedEmail}";
                _cache.Set(cacheKey, verificationCode, TimeSpan.FromMinutes(10));

                var subject = "Your PLV Account Verification Code";
                var content = $"<p>Hello,</p><p>Thank you for registering. Please use the following verification code to complete your signup process. The code is valid for 10 minutes.</p><p style='font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px; margin: 20px 0;'>{verificationCode}</p><p>If you did not request this, please ignore this email.</p>";
                var logoPath = ResolveEmailLogoPath();
                var htmlBody = CreateHtmlEmail(subject, content, useInlineLogo: logoPath != null);

                await _emailService.SendEmailAsync(normalizedEmail, subject, htmlBody, true, logoPath, EmailLogoContentId);

                return Ok(new { status = "Success", message = "Verification code sent to your email." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = $"Failed to process request: {ex.Message}" });
            }
        }

        [HttpPost("request")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> RequestAccess([FromBody] SignupRequest request)
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return StatusCode(StatusCodes.Status410Gone, new { status = "Error", message = "Public registration has been disabled. Accounts are created by authorized administrators." });
            }
            if (string.IsNullOrEmpty(request.Email))
            {
                return BadRequest(new { status = "Error", message = "Email is required." });
            }

            var normalizedEmail = request.Email.Trim().ToLower();
            request.Role = NormalizeSystemRole(request.Role);
            var inputCode = request.VerificationCode?.Trim();

            // 1. Verify Code
            if (!_cache.TryGetValue($"verification_{normalizedEmail}", out string? cachedCode) || cachedCode != inputCode)
            {
                return BadRequest(new { status = "Error", message = "The verification code is incorrect or has expired. Please try again." });
            }
            _cache.Remove($"verification_{normalizedEmail}");

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                // Check if user already exists before proceeding
                using (var checkCmd = new NpgsqlCommand("SELECT COUNT(1) FROM Users WHERE email = @email", conn))
                {
                    checkCmd.Parameters.AddWithValue("email", normalizedEmail);
                    long userCount = (long)(await checkCmd.ExecuteScalarAsync() ?? 0);
                    if (userCount > 0)
                    {
                        return BadRequest(new { status = "Error", message = "An account with this email already exists or is currently pending approval." });
                    }
                }

                using var transaction = await conn.BeginTransactionAsync();

                DateTime? parsedDob = null;
                if (request.Role?.ToLower() == "student" && !string.IsNullOrEmpty(request.DateOfBirth))
                {
                    string[] formats = { "MM/dd/yyyy", "M/d/yyyy", "MM/d/yyyy", "M/dd/yyyy", "yyyy-MM-dd" };
                    if (DateTime.TryParseExact(request.DateOfBirth, formats, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out DateTime dob))
                    {
                        parsedDob = dob;
                        request.DateOfBirth = dob.ToString("MM/dd/yyyy");
                    }
                    else
                    {
                        return BadRequest(new { status = "Error", message = "Invalid DOB format. Use mm/dd/yyyy." });
                    }
                }

                string finalPassword = "";
                if (request.Role?.ToLower() == "student")
                {
                    finalPassword = request.DateOfBirth ?? "";
                }
                else
                {
                    finalPassword = request.Password ?? "";
                }
                
                if (string.IsNullOrEmpty(finalPassword))
                {
                    _logger.LogWarning("Password/DOB validation failed for role '{Role}'. DOB: '{DOB}', Password Provided: {PassProvided}", request.Role, request.DateOfBirth, !string.IsNullOrEmpty(request.Password));
                    return BadRequest(new { status = "Error", message = request.Role?.ToLower() == "student" ? 
                        "Date of birth (mm/dd/yyyy) is required for students." : "Password is required." });
                }

                using var cmdUser = new NpgsqlCommand(@"
                    INSERT INTO Users (email, password_hash, role, status) 
                    VALUES (@email, crypt(@password, gen_salt('bf', 12)), @role, 'pending') RETURNING id", conn, transaction);
                cmdUser.Parameters.AddWithValue("email", normalizedEmail);
                cmdUser.Parameters.AddWithValue("password", finalPassword);
                cmdUser.Parameters.AddWithValue("role", request.Role?.ToLower() ?? "student");
                
                int userId = (int)(await cmdUser.ExecuteScalarAsync() ?? throw new Exception("Failed to retrieve new User ID"));

                string profileQuery = "";
                if (request.Role?.ToLower() == "student")
                {
                    profileQuery = @"INSERT INTO StudentProfiles (user_id, full_name, student_no, department, date_of_birth) 
                                   VALUES (@uid, @name, @studentno, @dept, @dob)";
                }
                else if (request.Role?.ToLower() == "faculty")
                {
                    profileQuery = "INSERT INTO FacultyProfiles (user_id, full_name, department, faculty_type) VALUES (@uid, @name, @dept, @facultyType)";
                }
                else 
                {
                    profileQuery = "INSERT INTO AdminProfiles (user_id, full_name, admin_level, department) VALUES (@uid, @name, @role, @dept)";
                }

                using var cmdProfile = new NpgsqlCommand(profileQuery, conn, transaction);
                cmdProfile.Parameters.AddWithValue("uid", userId);
                cmdProfile.Parameters.AddWithValue("name", request.FullName);
                cmdProfile.Parameters.AddWithValue("dept", (object?)request.Department ?? DBNull.Value);
                cmdProfile.Parameters.AddWithValue("role", request.Role ?? "");
                cmdProfile.Parameters.AddWithValue("facultyType", request.Role?.ToLower() == "faculty" ? (object?)(request.FacultyType ?? "full-time") : DBNull.Value);
                
                if (request.Role?.ToLower() == "student") 
                {
                    cmdProfile.Parameters.AddWithValue("studentno", (object?)request.StudentNo ?? DBNull.Value);
                    if (parsedDob.HasValue)
                    {
                        cmdProfile.Parameters.AddWithValue("dob", parsedDob.Value.Date);
                    }
                }

                await cmdProfile.ExecuteNonQueryAsync();
                await transaction.CommitAsync();

                if (request.Role?.ToLower() == "student")
                {
                    var subject = "Your PLV Account - Default Password Info";
                    var content = $@"<p>Hello {request.FullName},</p>
                                   <p>Your account default password is your Date of Birth: <strong>{finalPassword}</strong></p>
                                   <p>You can change it after first login. Await registrar approval.</p>";
                    var htmlBody = CreateHtmlEmail(subject, content);
                    await _emailService.SendEmailAsync(normalizedEmail, subject, htmlBody, true);
                }

                _cache.Remove("pending_requests");
                await _chatHubContext.Clients.Group("role_registrar").SendAsync("NewRegistrationRequest", new
                {
                    RequestId = userId,
                    FullName = request.FullName,
                    Email = normalizedEmail,
                    Role = request.Role?.ToLower() ?? "student",
                    Department = request.Department,
                    CreatedAt = DateTime.UtcNow
                });

                await NotifyAcademicDataChangedAsync("registration_requested", request.Department, normalizedEmail);
                return Ok(new { status = "Success", message = $"Registration request added. {(request.Role?.ToLower() == "student" ? $"Default password: {finalPassword} (will be emailed)" : "Password secured.")}" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = $"Registration failed: {ex.Message}" });
            }
        }

        [HttpGet("requests/pending")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> GetPendingRequests()
        {
            const string cacheKey = "pending_requests";
            if (_cache.TryGetValue(cacheKey, out object? cachedData) && cachedData != null)
            {
                return Ok(cachedData);
            }

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            var studentRequests = new List<object>();
            var staffRequests = new List<object>();

            using (var cmd = new NpgsqlCommand(@"
                    SELECT u.id, sp.full_name, u.email, u.role, sp.department, sp.student_no, u.status 
                    FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id 
                    WHERE u.role = 'student' AND u.status = 'pending'", conn))
            using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                {
                    studentRequests.Add(new {
                        requestid = reader.GetInt32(0),
                        fullname = reader.GetString(1),
                        email = reader.GetString(2),
                        role = reader.GetString(3),
                        department = reader.IsDBNull(4) ? null : reader.GetString(4),
                        studentno = reader.GetString(5),
                        requeststatus = reader.GetString(6)
                    });
                }
            }

            using (var cmd = new NpgsqlCommand(@"
                    SELECT u.id, fp.full_name, u.email, u.role, fp.department, u.status 
                    FROM Users u JOIN FacultyProfiles fp ON u.id = fp.user_id 
                    WHERE u.role = 'faculty' AND u.status = 'pending'
                    UNION
                    SELECT u.id, ap.full_name, u.email, u.role, ap.department, u.status 
                    FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id 
                    WHERE (
                        u.role = 'registrar'
                        OR LOWER(REPLACE(REPLACE(u.role, ' ', '_'), '-', '_')) IN ('department_admin', 'dept_admin', 'deptadmin', 'department', 'admin', 'chairperson')
                    ) AND u.status = 'pending'", conn))
            using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                {
                    staffRequests.Add(new {
                        requestid = reader.GetInt32(0),
                        fullname = reader.GetString(1),
                        email = reader.GetString(2),
                        role = reader.IsDBNull(3) ? null : reader.GetString(3),
                        department = reader.IsDBNull(4) ? null : reader.GetString(4),
                        requeststatus = reader.GetString(5)
                    });
                }
            }

            var response = new { status = "Success", studentRequests, staffRequests };
            var cacheEntryOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(5));
            _cache.Set(cacheKey, response, cacheEntryOptions);

            return Ok(response);
        }

        [HttpPut("requests/approve/{type}/{id}")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> ApproveRequest(string type, int id)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var transaction = await conn.BeginTransactionAsync();

            string query = "UPDATE Users SET status = 'APPROVED' WHERE id = @id AND status = 'pending' RETURNING email, role";

            using var cmd = new NpgsqlCommand(query, conn, transaction);
            cmd.Parameters.AddWithValue("id", id); 
            
            using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                return NotFound(new { status = "Error", message = "Registration request not found or already approved." });
            }
            
            string userEmail = reader.GetString(0) ?? "";
            string userRole = NormalizeSystemRole(reader.GetString(1));
            await reader.CloseAsync(); 

            using (var normalizeRoleCmd = new NpgsqlCommand("UPDATE Users SET role = @role WHERE id = @id", conn, transaction))
            {
                normalizeRoleCmd.Parameters.AddWithValue("role", userRole);
                normalizeRoleCmd.Parameters.AddWithValue("id", id);
                await normalizeRoleCmd.ExecuteNonQueryAsync();
            }

            using var client = _httpClientFactory.CreateClient("FabricCAClient");
            var apiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY") ?? _configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
            client.DefaultRequestHeaders.Add("x-api-key", apiKey);

            var payload = new { email = userEmail, role = userRole };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            
            var middlewareUrl = _configuration["Middleware:Url"] ?? _configuration["MIDDLEWARE_URL"] ?? "http://127.0.0.1:4000";
            var response = await client.PostAsync($"{middlewareUrl}/api/fabric/register-user", content);
            
            if (!response.IsSuccessStatusCode) {
                await transaction.RollbackAsync();
                string errorBody = await response.Content.ReadAsStringAsync();
                return StatusCode(500, new { status = "Error", message = $"Blockchain Wallet failed to create. Database changes rolled back. Middleware Error: {errorBody}" });
            }

            await transaction.CommitAsync();

            var emailSubject = "PLV System Access Approved";
            var emailContent = $"<p>Hello,</p><p>Your registration request for the role '<strong>{userRole}</strong>' has been approved. You can now log in to the system.</p>";
            _ = _emailService.SendEmailAsync(userEmail, emailSubject, CreateHtmlEmail(emailSubject, emailContent), true);

            _cache.Remove("pending_requests");
            if (userRole == "student") _cache.Remove("approved_students");
            else if (userRole == "faculty") _cache.Remove("approved_faculties");
            else if (userRole == "department_admin") _cache.Remove("approved_department_admins");

            await NotifyAcademicDataChangedAsync("registration_approved", null, userEmail);
            return Ok(new { status = "Success", message = "Request approved and Fabric Wallet created successfully." });
        }

        [HttpDelete("requests/deny/{id}")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> DenyRequest(int id)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            using var findCmd = new NpgsqlCommand("SELECT email, role FROM Users WHERE id = @id AND status = 'pending'", conn);
            findCmd.Parameters.AddWithValue("id", id);
            using var reader = await findCmd.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                return NotFound(new { status = "Error", message = "Request not found or already actioned." });
            }
            string userEmail = reader.GetString(0);
            string userRole = reader.GetString(1);
            await reader.CloseAsync();

            using var deleteCmd = new NpgsqlCommand("DELETE FROM Users WHERE id = @id", conn);
            deleteCmd.Parameters.AddWithValue("id", id);
            await deleteCmd.ExecuteNonQueryAsync();

            var emailSubject = "PLV System Access Update";
            var emailContent = $"<p>Hello,</p><p>We regret to inform you that your registration request for the role '<strong>{userRole}</strong>' has been denied by the administration.</p>";
            _ = _emailService.SendEmailAsync(userEmail, emailSubject, CreateHtmlEmail(emailSubject, emailContent), true);

            _cache.Remove("pending_requests");
            await NotifyAcademicDataChangedAsync("registration_denied", null, userEmail);
            return Ok(new { status = "Success", message = "Request denied and removed." });
        }

        [HttpDelete("requests/cleanup-pending")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> CleanupPendingRequests()
        {
            var requestApiKey = Request.Headers["x-api-key"].ToString();
            var configuredApiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY") ?? _configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
            if (requestApiKey != configuredApiKey)
            {
                return StatusCode(403, new { status = "Error", message = "Unauthorized. Invalid Internal API Key." });
            }

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                
                using var cmd = new NpgsqlCommand("DELETE FROM Users WHERE status = 'pending' AND created_at < NOW() - INTERVAL '30 days'", conn);
                int deletedCount = await cmd.ExecuteNonQueryAsync();

                _cache.Remove("pending_requests");

                return Ok(new { status = "Success", message = $"Successfully cleaned up {deletedCount} orphaned pending requests." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = $"Database error: {ex.Message}" });
            }
        }

        [HttpGet("students/approved")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> GetApprovedStudents()
        {
            const string cacheKey = "approved_students";
            if (_cache.TryGetValue(cacheKey, out object? cachedData) && cachedData != null)
            {
                return Ok(cachedData);
            }

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var students = new List<object>();

                using (var cmd = new NpgsqlCommand(@"
                    SELECT u.id, sp.full_name, u.email, sp.department, sp.student_no, sp.section,
                           sp.assignment_status, COALESCE(sp.year_level, enrollment.year_level::text),
                           COALESCE(sp.curriculum_id, enrollment.curriculum_id),
                           curriculum.curriculum_name, curriculum.curriculum_version,
                           enrollment.school_year, enrollment.semester, enrollment.status
                    FROM Users u
                    JOIN StudentProfiles sp ON u.id = sp.user_id
                    LEFT JOIN LATERAL (
                        SELECT se.curriculum_id, se.year_level, se.school_year, se.semester, se.status
                        FROM student_enrollments se
                        WHERE se.student_user_id = u.id
                        ORDER BY se.updated_at DESC, se.enrollment_id DESC
                        LIMIT 1
                    ) enrollment ON TRUE
                    LEFT JOIN curriculums curriculum
                      ON curriculum.curriculum_id = COALESCE(sp.curriculum_id, enrollment.curriculum_id)
                    WHERE LOWER(u.role) = 'student' AND LOWER(u.status) = 'approved' AND u.is_active = TRUE
                    ORDER BY sp.full_name", conn))
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        students.Add(new {
                            id = reader.GetInt32(0),
                            fullname = reader.GetString(1),
                            email = reader.GetString(2),
                            department = reader.IsDBNull(3) ? null : reader.GetString(3),
                            studentno = reader.IsDBNull(4) ? null : reader.GetString(4),
                            section = reader.IsDBNull(5) ? null : reader.GetString(5),
                            assignmentStatus = reader.IsDBNull(6) ? "Unassigned" : reader.GetString(6),
                            yearLevel = reader.IsDBNull(7) ? null : reader.GetString(7),
                            curriculumId = reader.IsDBNull(8) ? (long?)null : reader.GetInt64(8),
                            curriculumName = reader.IsDBNull(9) ? null : reader.GetString(9),
                            curriculumVersion = reader.IsDBNull(10) ? null : reader.GetString(10),
                            schoolYear = reader.IsDBNull(11) ? null : reader.GetString(11),
                            semester = reader.IsDBNull(12) ? null : reader.GetString(12),
                            enrollmentStatus = reader.IsDBNull(13) ? null : reader.GetString(13)
                        });
                    }
                }

                var response = new { status = "Success", students };
                var cacheEntryOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(5));
                _cache.Set(cacheKey, response, cacheEntryOptions);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("students/unassigned-enrolled")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> GetUnassignedEnrolledStudents(
            [FromQuery] string? department, [FromQuery] string? yearLevel,
            [FromQuery] string? schoolYear, [FromQuery] string? semester)
        {
            try
            {
                short? year = string.IsNullOrWhiteSpace(yearLevel) ? null : NormalizeYearLevel(yearLevel);
                var periodYear = string.IsNullOrWhiteSpace(schoolYear) ? null : NormalizeSchoolYear(schoolYear);
                var periodSemester = string.IsNullOrWhiteSpace(semester) ? null : NormalizeEnrollmentSemester(semester);
                await using var connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync();
                var students = await EnrollmentSectioningService.GetUnassignedAsync(connection,
                    string.IsNullOrWhiteSpace(department) ? null : department.Trim(), year, periodYear, periodSemester, null);
                return Ok(new { status = "Success", data = students });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
        }

        public sealed class AssignEnrolledStudentsRequest
        {
            public string[] StudentIds { get; set; } = Array.Empty<string>();
            public string SchoolYear { get; set; } = "";
            public string Semester { get; set; } = "";
            public Dictionary<string, int>? ExpectedSectionIds { get; set; }
        }

        [HttpPost("sections/{id:int}/assign-students")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> AssignEnrolledStudents(int id, [FromBody] AssignEnrolledStudentsRequest request)
        {
            try
            {
                if (id <= 0 || string.IsNullOrWhiteSpace(request.SchoolYear) || string.IsNullOrWhiteSpace(request.Semester))
                    throw new ArgumentException("A valid section ID, school year and semester are required.");
                var schoolYear = NormalizeSchoolYear(request.SchoolYear);
                var semester = NormalizeEnrollmentSemester(request.Semester);
                await using var connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync();
                var result = await EnrollmentSectioningService.AssignAsync(connection, id,
                    request.StudentIds ?? Array.Empty<string>(), schoolYear, semester, null, request.ExpectedSectionIds);
                _cache.Remove("approved_students");
                await SafeNotifyAcademicDataChangedAsync("students_section_assigned", result.Department, User.Identity?.Name);
                return Ok(new { status = "Success", assignedCount = result.Count });
            }
            catch (ArgumentException ex) { return BadRequest(new { status = "Error", message = ex.Message }); }
            catch (KeyNotFoundException ex) { return NotFound(new { status = "Error", message = ex.Message }); }
            catch (InvalidOperationException ex) { return Conflict(new { status = "Error", message = ex.Message }); }
        }

        [HttpGet("students/next-id")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> GetNextStudentId([FromQuery] string year)
        {
            var normalizedYear = year?.Trim() ?? string.Empty;
            if (!System.Text.RegularExpressions.Regex.IsMatch(normalizedYear, @"^\d{4}$"))
                return BadRequest(new { status = "Error", message = "Year must be a four-digit value." });

            var prefix = normalizedYear.Substring(2, 2);
            var pattern = new System.Text.RegularExpressions.Regex(
                $@"^{System.Text.RegularExpressions.Regex.Escape(prefix)}-(\d{{4}})$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant);
            var highestSequence = 0;

            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT student_no FROM studentprofiles WHERE student_no LIKE @prefix", conn);
            command.Parameters.AddWithValue("prefix", $"{prefix}-%");
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                if (reader.IsDBNull(0)) continue;
                var match = pattern.Match(reader.GetString(0).Trim());
                if (match.Success && int.TryParse(match.Groups[1].Value, out var sequence))
                    highestSequence = Math.Max(highestSequence, sequence);
            }

            return Ok(new
            {
                status = "Success",
                year = normalizedYear,
                prefix,
                highestSequence,
                nextStudentId = highestSequence < 9999 ? $"{prefix}-{highestSequence + 1:0000}" : null
            });
        }

        [HttpPut("students/{id}/assign")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> AssignStudent(int id, [FromBody] AssignStudentRequest request)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await using var transaction = await conn.BeginTransactionAsync();

                string userEmail = "", userName = "Student", studentNo = "";
                using (var cmdEmail = new NpgsqlCommand(@"
                    SELECT u.email, sp.full_name, COALESCE(sp.student_no, u.username, u.email)
                    FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id
                    WHERE u.id = @id AND LOWER(u.role) = 'student'", conn, transaction))
                {
                    cmdEmail.Parameters.AddWithValue("id", id); 
                    using var reader = await cmdEmail.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userEmail = reader.GetString(0);
                        userName = reader.GetString(1);
                        studentNo = reader.GetString(2);
                    }
                }

                if (string.IsNullOrWhiteSpace(userEmail)) return NotFound(new { status = "Error", message = "Student profile not found." });
                var program = await ResolveEnrollmentProgramAsync(conn, transaction, request.Department);
                var yearLevel = NormalizeYearLevel(request.YearLevel, request.Section);
                var section = NormalizeEnrollmentSection(request.Section, yearLevel);
                var schoolYear = NormalizeSchoolYear(request.SchoolYear);
                var semester = NormalizeEnrollmentSemester(request.Semester);
                var curriculumId = await ResolveEnrollmentCurriculumAsync(conn, transaction, program.Id, request.CurriculumId, null);
                var sectionId = await EnsureEnrollmentSectionAsync(conn, transaction, program.Name, yearLevel, section);

                string query = @"
                    UPDATE StudentProfiles
                    SET department = @dept, section = @section, year_level = @yearLevel,
                        curriculum_id = @curriculumId, assignment_status = 'Enrolled'
                    WHERE user_id = @id";
                using var cmd = new NpgsqlCommand(query, conn, transaction);
                cmd.Parameters.AddWithValue("dept", program.Name);
                cmd.Parameters.AddWithValue("section", section);
                cmd.Parameters.AddWithValue("yearLevel", yearLevel.ToString());
                cmd.Parameters.AddWithValue("curriculumId", (object?)curriculumId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("id", id);
                
                int rows = await cmd.ExecuteNonQueryAsync();
                if (rows == 0) return NotFound(new { status = "Error", message = "Student profile not found." });

                await UpsertStudentEnrollmentAsync(conn, transaction, id, studentNo, program.Id, curriculumId,
                    sectionId, schoolYear, semester, yearLevel, section, User.Identity?.Name ?? "registrar");
                await _auditLog.LogAsync(User.Identity?.Name ?? "registrar", "registrar", "STUDENT_ENROLLED",
                    "student_enrollment", id.ToString(), null,
                    new { studentNo, program = program.Code, curriculumId, schoolYear, semester, yearLevel, section },
                    "Registrar assigned the student's official academic-period enrollment.", HttpContext.Connection.RemoteIpAddress?.ToString(),
                    conn, transaction);
                await transaction.CommitAsync();

                var emailSubject = "PLV Enrollment Update: Department Assignment";
                var emailContent = $"<p>Hello {userName},</p><p>The Registrar has officially enrolled you in <strong>{program.Name}</strong>, section <strong>{section}</strong>, for <strong>{schoolYear} {semester}</strong>.</p>";
                _ = _emailService.SendEmailAsync(userEmail, emailSubject, CreateHtmlEmail(emailSubject, emailContent), true);

                _cache.Remove("approved_students");

                await NotifyAcademicDataChangedAsync("student_enrolled", program.Name, userEmail);
                return Ok(new { status = "Success", message = "Student enrollment saved.", curriculumId, schoolYear, semester, yearLevel });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpDelete("students/{id}/drop")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> DropStudent(int id)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var findCmd = new NpgsqlCommand("SELECT email, role FROM Users WHERE id = @id AND role = 'student'", conn);
                findCmd.Parameters.AddWithValue("id", id);
                using var reader = await findCmd.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return NotFound(new { status = "Error", message = "Student not found." });
                }
                string userEmail = reader.GetString(0);
                string userRole = reader.GetString(1);
                await reader.CloseAsync();

                using var client = _httpClientFactory.CreateClient("FabricCAClient");
                var apiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY") ?? _configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
                client.DefaultRequestHeaders.Add("x-api-key", apiKey);

                var payload = new { username = userEmail, role = userRole };
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var middlewareUrl = _configuration["Middleware:Url"] ?? _configuration["MIDDLEWARE_URL"] ?? "http://127.0.0.1:4000";
                var response = await client.PostAsync($"{middlewareUrl}/api/revoke", content);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errBody = await response.Content.ReadAsStringAsync();
                    if (errBody.Contains("already revoked") || errBody.Contains("already inactive"))
                    {
                        _logger.LogWarning("WBSD 1.29.2: Account {Email} is already revoked on the CA.", userEmail);
                    }
                }

                using var tx = await conn.BeginTransactionAsync();

                using var dropEnrollmentCmd = new NpgsqlCommand(@"
                    UPDATE student_enrollments
                    SET status = 'DROPPED', updated_at = CURRENT_TIMESTAMP
                    WHERE student_user_id = @id AND status = 'ENROLLED'", conn, tx);
                dropEnrollmentCmd.Parameters.AddWithValue("id", id);
                await dropEnrollmentCmd.ExecuteNonQueryAsync();

                using var delProfileCmd = new NpgsqlCommand("DELETE FROM StudentProfiles WHERE user_id = @id", conn, tx);
                delProfileCmd.Parameters.AddWithValue("id", id);
                await delProfileCmd.ExecuteNonQueryAsync();

                using var deleteCmd = new NpgsqlCommand("DELETE FROM Users WHERE id = @id", conn, tx);
                deleteCmd.Parameters.AddWithValue("id", id);
                await deleteCmd.ExecuteNonQueryAsync();

                await tx.CommitAsync();

                await SafeInsertAuthAuditLogAsync(
                    conn,
                    "SYSTEM-AUTH",
                    userEmail,
                    "DROPPED",
                    "Student Access Revoked",
                    User.Identity?.Name ?? "Admin"
                );

                _cache.Remove("approved_students");
                await SafeNotifyAcademicDataChangedAsync("student_dropped", null, userEmail);
                return Ok(new { status = "Success", message = "Student dropped and access revoked." });
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        [HttpGet("admins/department/approved")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> GetApprovedDepartmentAdmins()
        {
            const string cacheKey = "approved_department_admins";
            if (_cache.TryGetValue(cacheKey, out object? cachedData) && cachedData != null)
            {
                return Ok(cachedData);
            }

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var admins = new List<object>();

                using (var cmd = new NpgsqlCommand(@"
                    SELECT u.id, ap.full_name, u.email, ap.department, u.role 
                    FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id 
                    WHERE LOWER(REPLACE(REPLACE(u.role, ' ', '_'), '-', '_')) IN ('department_admin', 'dept_admin', 'deptadmin', 'department', 'admin', 'chairperson')
                      AND u.status = 'APPROVED'", conn))
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        admins.Add(new {
                            id = reader.GetInt32(0),
                            fullname = reader.GetString(1),
                            email = reader.GetString(2),
                            department = reader.IsDBNull(3) ? "Unassigned" : reader.GetString(3),
                            role = NormalizeSystemRole(reader.GetString(4))
                        });
                    }
                }

                var response = new { status = "Success", admins };
                var cacheEntryOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(5));
                _cache.Set(cacheKey, response, cacheEntryOptions);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPut("admins/department/{id}/assign")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> AssignDepartmentAdmin(int id, [FromBody] AssignAdminRequest request)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                string userEmail = "", userName = "Admin";
                using (var cmdEmail = new NpgsqlCommand("SELECT u.email, ap.full_name FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id WHERE u.id = @id", conn))
                {
                    cmdEmail.Parameters.AddWithValue("id", id); 
                    using var reader = await cmdEmail.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userEmail = reader.GetString(0);
                        userName = reader.GetString(1);
                    }
                }

                string queryAdmin = "UPDATE AdminProfiles SET department = @dept WHERE user_id = @id";
                using var cmdAdmin = new NpgsqlCommand(queryAdmin, conn);
                cmdAdmin.Parameters.AddWithValue("dept", (object?)request.Department?.Trim() ?? DBNull.Value);
                cmdAdmin.Parameters.AddWithValue("id", id);
                
                int rows = await cmdAdmin.ExecuteNonQueryAsync();

                if (rows == 0) return NotFound(new { status = "Error", message = "Admin profile not found." });

                var emailSubject = "PLV Assignment: Department Head";
                var emailContent = $"<p>Hello {userName},</p><p>You have been officially assigned as the head of the <strong>{request.Department}</strong> department.</p>";
                _ = _emailService.SendEmailAsync(userEmail, emailSubject, CreateHtmlEmail(emailSubject, emailContent), true);

                _cache.Remove("approved_department_admins");

                await NotifyAcademicDataChangedAsync("department_admin_assigned", request.Department, userEmail);
                return Ok(new { status = "Success", message = "Department assigned successfully." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpDelete("admins/department/{id}/revoke")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> RevokeDepartmentAdmin(int id)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var findCmd = new NpgsqlCommand(@"
                    SELECT u.email, u.role, ap.full_name, ap.department
                    FROM Users u
                    JOIN AdminProfiles ap ON u.id = ap.user_id
                    WHERE u.id = @id
                      AND LOWER(REPLACE(REPLACE(u.role, ' ', '_'), '-', '_')) IN ('department_admin', 'dept_admin', 'deptadmin', 'department', 'admin', 'chairperson')", conn);
                findCmd.Parameters.AddWithValue("id", id);

                using var reader = await findCmd.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                {
                    return NotFound(new { status = "Error", message = "Department admin/chairperson not found." });
                }

                string userEmail = reader.GetString(0);
                string userRole = reader.GetString(1);
                string userName = reader.IsDBNull(2) ? userEmail : reader.GetString(2);
                string department = reader.IsDBNull(3) ? "Unassigned" : reader.GetString(3);
                await reader.CloseAsync();

                using var client = _httpClientFactory.CreateClient("FabricCAClient");
                var apiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY") ?? _configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
                client.DefaultRequestHeaders.Add("x-api-key", apiKey);

                var payload = new { username = userEmail, role = userRole };
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var middlewareUrl = _configuration["Middleware:Url"] ?? _configuration["MIDDLEWARE_URL"] ?? "http://127.0.0.1:4000";
                var response = await client.PostAsync($"{middlewareUrl}/api/revoke", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errBody = await response.Content.ReadAsStringAsync();
                    if (errBody.Contains("already revoked") || errBody.Contains("already inactive") || errBody.Contains("does not exist") || errBody.Contains("not found"))
                    {
                        _logger.LogWarning("Chairperson account {Email} is already revoked or missing from the Fabric wallet/CA.", userEmail);
                    }
                    else
                    {
                        return StatusCode(502, new { status = "Error", message = $"Fabric revocation failed: {errBody}" });
                    }
                }

                using var tx = await conn.BeginTransactionAsync();

                using var delProfileCmd = new NpgsqlCommand("DELETE FROM AdminProfiles WHERE user_id = @id", conn, tx);
                delProfileCmd.Parameters.AddWithValue("id", id);
                await delProfileCmd.ExecuteNonQueryAsync();

                using var deleteCmd = new NpgsqlCommand("DELETE FROM Users WHERE id = @id", conn, tx);
                deleteCmd.Parameters.AddWithValue("id", id);
                await deleteCmd.ExecuteNonQueryAsync();

                await tx.CommitAsync();

                await SafeInsertAuthAuditLogAsync(
                    conn,
                    "SYSTEM-AUTH",
                    userEmail,
                    "REVOKED",
                    $"Chairperson Access Revoked ({department})",
                    User.Identity?.Name ?? "Admin"
                );

                _cache.Remove("approved_department_admins");
                await SafeNotifyAcademicDataChangedAsync("department_admin_revoked", department, userEmail);
                return Ok(new { status = "Success", message = $"{userName} access revoked." });
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        [HttpGet("faculty/approved")]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> GetApprovedFaculties()
        {
            var actorEmail = User.Identity?.Name?.Trim().ToLowerInvariant() ?? "unknown";
            var cacheKey = User.IsInRole("registrar")
                ? "approved_faculties:registrar"
                : $"approved_faculties:department_admin:{actorEmail}";
            try
            {
                if (_cache.TryGetValue(cacheKey, out object? cachedData) && cachedData != null)
                {
                    return Ok(cachedData);
                }

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var faculties = new List<object>();

                using (var cmd = new NpgsqlCommand(@"
                    SELECT u.id, fp.full_name, u.email, fp.department, fp.section, fp.year_level 
                    FROM Users u JOIN FacultyProfiles fp ON u.id = fp.user_id 
                    WHERE u.role = 'faculty' AND u.status = 'APPROVED' AND u.is_active = TRUE
                      AND (
                        @isRegistrar = TRUE OR EXISTS (
                          SELECT 1
                          FROM users actor
                          JOIN adminprofiles actor_profile ON actor_profile.user_id = actor.id
                          JOIN academic_programs p
                            ON LOWER(actor_profile.department) IN (LOWER(p.program_code), LOWER(p.program_name))
                          WHERE LOWER(actor.email) = LOWER(@actorEmail)
                            AND LOWER(fp.department) IN (LOWER(p.program_code), LOWER(p.program_name))
                            AND p.is_active = TRUE
                        )
                      )
                    UNION
                    SELECT u.id, ap.full_name, u.email, ap.department, 'Unassigned' as section, 'Unassigned' as year_level 
                    FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id 
                    WHERE LOWER(REPLACE(REPLACE(u.role, ' ', '_'), '-', '_')) IN ('department_admin', 'dept_admin', 'deptadmin', 'department', 'admin', 'chairperson') 
                      AND u.status = 'APPROVED' AND u.is_active = TRUE
                      AND @isRegistrar = TRUE", conn))
                {
                    cmd.Parameters.AddWithValue("isRegistrar", User.IsInRole("registrar"));
                    cmd.Parameters.AddWithValue("actorEmail", actorEmail);
                    using var reader = await cmd.ExecuteReaderAsync();
                    while (await reader.ReadAsync())
                    {
                        faculties.Add(new {
                            id = reader.GetInt32(0),
                            fullname = reader.GetString(1),
                            email = reader.GetString(2),
                            department = reader.IsDBNull(3) ? "Unassigned" : reader.GetString(3),
                            section = reader.IsDBNull(4) ? "Unassigned" : reader.GetString(4),
                            yearLevel = reader.IsDBNull(5) ? "Unassigned" : reader.GetString(5)
                        });
                    }
                }

                var response = new { status = "Success", faculties };
                var cacheEntryOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(5));
                _cache.Set(cacheKey, response, cacheEntryOptions);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("faculty/assignment-options")]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> GetFacultyAssignmentOptions([FromQuery] string department)
        {
            if (string.IsNullOrWhiteSpace(department))
                return BadRequest(new { status = "Error", message = "An academic program is required." });
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync();
            if (!await CanManageAcademicProgramAsync(connection, department, HttpContext.RequestAborted))
                return Forbid();
            var sections = new List<object>();
            await using (var command = new NpgsqlCommand(@"
                SELECT s.id, p.program_code, p.program_name, s.year_level, s.section_num
                FROM academicsections s
                JOIN academic_programs p
                  ON LOWER(s.department) IN (LOWER(p.program_code), LOWER(p.program_name))
                WHERE p.is_active = TRUE
                  AND LOWER(@department) IN (LOWER(p.program_code), LOWER(p.program_name))
                ORDER BY s.year_level, s.section_num;", connection))
            {
                command.Parameters.AddWithValue("department", department.Trim());
                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                    sections.Add(new
                    {
                        id = reader.GetInt32(0), programCode = reader.GetString(1), department = reader.GetString(2),
                        yearLevel = reader.GetInt32(3), sectionNumber = reader.GetInt32(4),
                        section = $"{reader.GetInt32(3)}-{reader.GetInt32(4)}"
                    });
            }
            var subjects = new List<object>();
            await using (var command = new NpgsqlCommand(@"
                SELECT cs.subject_code, cs.subject_title, cs.year_level, cs.semester
                FROM curriculum_subjects cs
                JOIN curriculums c ON c.curriculum_id = cs.curriculum_id AND c.status = 'PUBLISHED'
                JOIN academic_programs p ON p.program_id = c.program_id
                WHERE LOWER(@department) IN (LOWER(p.program_code), LOWER(p.program_name))
                ORDER BY cs.year_level, cs.semester, cs.subject_code;", connection))
            {
                command.Parameters.AddWithValue("department", department.Trim());
                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                    subjects.Add(new
                    {
                        subjectCode = reader.GetString(0), subjectTitle = reader.GetString(1),
                        yearLevel = reader.GetInt16(2), semester = reader.GetString(3)
                    });
            }
            var enrollmentPeriods = new List<object>();
            await using (var command = new NpgsqlCommand(@"
                SELECT DISTINCT se.school_year, se.semester, se.year_level,
                       COALESCE(se.section, CONCAT(se.year_level, '-', s.section_num)),
                       se.academic_section_id
                FROM student_enrollments se
                JOIN academic_programs p ON p.program_id = se.program_id
                LEFT JOIN academicsections s ON s.id = se.academic_section_id
                WHERE LOWER(@department) IN (LOWER(p.program_code), LOWER(p.program_name))
                  AND se.status = 'ENROLLED'
                ORDER BY se.school_year DESC, se.semester, se.year_level, COALESCE(se.section, CONCAT(se.year_level, '-', s.section_num));", connection))
            {
                command.Parameters.AddWithValue("department", department.Trim());
                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var semester = NormalizeEnrollmentSemester(reader.GetString(1));
                    enrollmentPeriods.Add(new
                    {
                        schoolYear = reader.GetString(0), semester,
                        semesterDisplay = semester switch { "FIRST" => "1st Semester", "SECOND" => "2nd Semester", _ => "Summer / Midyear" },
                        yearLevel = reader.GetInt16(2), section = reader.IsDBNull(3) ? "" : reader.GetString(3),
                        academicSectionId = reader.IsDBNull(4) ? (int?)null : reader.GetInt32(4)
                    });
                }
            }
            return Ok(new
            {
                status = "Success", sections, subjects, enrollmentPeriods,
                semesterAliases = new Dictionary<string, string[]>
                {
                    ["FIRST"] = new[] { "FIRST", "First Semester", "1st Semester" },
                    ["SECOND"] = new[] { "SECOND", "Second Semester", "2nd Semester" },
                    ["MIDYEAR"] = new[] { "MIDYEAR", "Midyear", "Summer" }
                }
            });
        }

        [HttpPut("faculty/{id}/assign")]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> AssignFaculty(int id, [FromBody] AssignFacultyRequest request)
        {
            try
            {
                if (id <= 0 || string.IsNullOrWhiteSpace(request.Department) ||
                    string.IsNullOrWhiteSpace(request.Section) || string.IsNullOrWhiteSpace(request.YearLevel))
                    throw new ArgumentException("Faculty, academic program, year level, and section are required.");
                var yearMatch = System.Text.RegularExpressions.Regex.Match(request.YearLevel.Trim(), @"^([1-4])(?:st|nd|rd|th)?(?:\s+year)?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (!yearMatch.Success) throw new ArgumentException("Year level must be from 1 to 4.");
                var yearLevel = int.Parse(yearMatch.Groups[1].Value);
                var sectionMatch = System.Text.RegularExpressions.Regex.Match(
                    request.Section.Trim(),
                    @"^(?:(?:.*\s)?([1-4])\s*-\s*)?(\d+)$");
                if (!sectionMatch.Success || !int.TryParse(sectionMatch.Groups[2].Value, out var sectionNumber) || sectionNumber < 1)
                    throw new ArgumentException("Section must be a positive section number or use a section name ending in year-section format, for example 2-1 or BSIT 2-1.");
                if (sectionMatch.Groups[1].Success && int.Parse(sectionMatch.Groups[1].Value) != yearLevel)
                    throw new ArgumentException("Section year must match the selected year level.");

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                if (!await CanManageAcademicProgramAsync(conn, request.Department, HttpContext.RequestAborted))
                    return Forbid();

                string canonicalDepartment;
                await using (var sectionCommand = new NpgsqlCommand(@"
                    SELECT p.program_name
                    FROM academicsections s
                    JOIN academic_programs p
                      ON LOWER(s.department) IN (LOWER(p.program_code), LOWER(p.program_name))
                    WHERE s.year_level = @yearLevel AND s.section_num = @sectionNumber
                      AND LOWER(@department) IN (LOWER(p.program_code), LOWER(p.program_name))
                      AND p.is_active = TRUE
                    LIMIT 1;", conn))
                {
                    sectionCommand.Parameters.AddWithValue("yearLevel", yearLevel);
                    sectionCommand.Parameters.AddWithValue("sectionNumber", sectionNumber);
                    sectionCommand.Parameters.AddWithValue("department", request.Department.Trim());
                    canonicalDepartment = (string?)await sectionCommand.ExecuteScalarAsync()
                        ?? throw new ArgumentException("The selected section does not exist in the academic program.");
                }
                var canonicalSubject = string.IsNullOrWhiteSpace(request.Subject) ? null : request.Subject.Trim();
                if (canonicalSubject is not null)
                {
                    await using var subjectCommand = new NpgsqlCommand(@"
                        SELECT 1
                        FROM curriculum_subjects cs
                        JOIN curriculums c ON c.curriculum_id = cs.curriculum_id AND c.status = 'PUBLISHED'
                        JOIN academic_programs p ON p.program_id = c.program_id
                        WHERE LOWER(p.program_name) = LOWER(@department)
                          AND cs.year_level = @yearLevel AND LOWER(cs.subject_code) = LOWER(@subject)
                        LIMIT 1;", conn);
                    subjectCommand.Parameters.AddWithValue("department", canonicalDepartment);
                    subjectCommand.Parameters.AddWithValue("yearLevel", yearLevel);
                    subjectCommand.Parameters.AddWithValue("subject", canonicalSubject);
                    if (await subjectCommand.ExecuteScalarAsync() is null)
                        throw new ArgumentException("The selected subject is not part of the published curriculum for this program and year level.");
                }

                string userEmail = "", userName = "Faculty";
                using (var cmdEmail = new NpgsqlCommand(@"
                    SELECT u.email, COALESCE(fp.full_name, ap.full_name) 
                    FROM Users u 
                    LEFT JOIN FacultyProfiles fp ON u.id = fp.user_id 
                    LEFT JOIN AdminProfiles ap ON u.id = ap.user_id 
                    WHERE u.id = @id AND LOWER(u.role) = 'faculty' AND LOWER(u.status) = 'approved' AND u.is_active = TRUE", conn))
                {
                    cmdEmail.Parameters.AddWithValue("id", id); 
                    using var reader = await cmdEmail.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userEmail = reader.GetString(0);
                        userName = reader.GetString(1);
                    }
                }

                if (string.IsNullOrWhiteSpace(userEmail))
                    return NotFound(new { status = "Error", message = "Active faculty account not found." });

                string updateProfileQuery = "UPDATE FacultyProfiles SET department = @dept WHERE user_id = @id AND (department IS NULL OR department = 'Unassigned')";
                using var cmdProfile = new NpgsqlCommand(updateProfileQuery, conn);
                cmdProfile.Parameters.AddWithValue("dept", canonicalDepartment);
                cmdProfile.Parameters.AddWithValue("id", id);
                await cmdProfile.ExecuteNonQueryAsync();

                var canonicalSectionLabel = request.Section.Trim();
                using (var migrateLegacySection = new NpgsqlCommand(@"
                    UPDATE FacultySections legacy
                    SET section = @canonicalSection
                    WHERE legacy.user_id = @id
                      AND legacy.department = @dept
                      AND legacy.year_level = @year
                      AND legacy.section = @legacySection
                      AND (legacy.subject = @subj OR (legacy.subject IS NULL AND @subj IS NULL))
                      AND NOT EXISTS (
                        SELECT 1 FROM FacultySections current
                        WHERE current.user_id = @id
                          AND current.department = @dept
                          AND current.year_level = @year
                          AND current.section = @canonicalSection
                          AND (current.subject = @subj OR (current.subject IS NULL AND @subj IS NULL))
                      );", conn))
                {
                    migrateLegacySection.Parameters.AddWithValue("id", id);
                    migrateLegacySection.Parameters.AddWithValue("dept", canonicalDepartment);
                    migrateLegacySection.Parameters.AddWithValue("year", yearLevel.ToString());
                    migrateLegacySection.Parameters.AddWithValue("legacySection", sectionNumber.ToString());
                    migrateLegacySection.Parameters.AddWithValue("canonicalSection", canonicalSectionLabel);
                    migrateLegacySection.Parameters.AddWithValue("subj", (object?)canonicalSubject ?? DBNull.Value);
                    await migrateLegacySection.ExecuteNonQueryAsync();
                }

                string insertSectionQuery = @"
                    INSERT INTO FacultySections (user_id, department, section, year_level, subject) 
                    VALUES (@id, @dept, @section, @year, @subj)
                    ON CONFLICT (user_id, department, section, subject) DO NOTHING";
                
                using var cmdSection = new NpgsqlCommand(insertSectionQuery, conn);
                cmdSection.Parameters.AddWithValue("id", id);
                cmdSection.Parameters.AddWithValue("dept", canonicalDepartment);
                cmdSection.Parameters.AddWithValue("section", canonicalSectionLabel);
                cmdSection.Parameters.AddWithValue("year", yearLevel.ToString());
                cmdSection.Parameters.AddWithValue("subj", (object?)canonicalSubject ?? DBNull.Value);

                int rows = await cmdSection.ExecuteNonQueryAsync();
                
                if (rows == 0) 
                {
                    return Ok(new { status = "Info", message = $"Faculty is already assigned to {canonicalDepartment} Section {yearLevel}-{sectionNumber}." });
                }

                var emailSubject = "PLV Faculty Assignment";
                var emailContent = $"<p>Hello {userName},</p><p>You have been officially assigned to handle Section <strong>{yearLevel}-{sectionNumber}</strong> for the <strong>{canonicalDepartment}</strong> program.</p>";
                _ = _emailService.SendEmailAsync(userEmail, emailSubject, CreateHtmlEmail(emailSubject, emailContent), true);

               _cache.Remove("approved_faculties");
                await NotifyAcademicDataChangedAsync("faculty_assigned", canonicalDepartment, userEmail);
                return Ok(new { status = "Success", message = "Faculty assigned successfully." });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpDelete("faculty/{id}/revoke")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> RevokeFaculty(int id)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var findCmd = new NpgsqlCommand("SELECT email, role FROM Users WHERE id = @id AND role = 'faculty'", conn);
                findCmd.Parameters.AddWithValue("id", id);
                using var reader = await findCmd.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return NotFound(new { status = "Error", message = "Faculty not found." });
                }
                string userEmail = reader.GetString(0);
                string userRole = reader.GetString(1);
                await reader.CloseAsync();

                using var client = _httpClientFactory.CreateClient("FabricCAClient");
                var apiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY") ?? _configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
                client.DefaultRequestHeaders.Add("x-api-key", apiKey);

                var payload = new { username = userEmail, role = userRole };
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var middlewareUrl = _configuration["Middleware:Url"] ?? _configuration["MIDDLEWARE_URL"] ?? "http://127.0.0.1:4000";
                var response = await client.PostAsync($"{middlewareUrl}/api/revoke", content);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errBody = await response.Content.ReadAsStringAsync();
                    if (errBody.Contains("already revoked") || errBody.Contains("already inactive"))
                        _logger.LogWarning("WBSD 1.29.2: Account {Email} is already revoked on the CA.", userEmail);
                }

                using var tx = await conn.BeginTransactionAsync();

                using var delSecCmd = new NpgsqlCommand("DELETE FROM FacultySections WHERE user_id = @id", conn, tx);
                delSecCmd.Parameters.AddWithValue("id", id);
                await delSecCmd.ExecuteNonQueryAsync();

                using var delProfileCmd = new NpgsqlCommand("DELETE FROM FacultyProfiles WHERE user_id = @id", conn, tx);
                delProfileCmd.Parameters.AddWithValue("id", id);
                await delProfileCmd.ExecuteNonQueryAsync();

                using var deleteCmd = new NpgsqlCommand("DELETE FROM Users WHERE id = @id", conn, tx);
                deleteCmd.Parameters.AddWithValue("id", id);
                await deleteCmd.ExecuteNonQueryAsync();

                await tx.CommitAsync();

                await SafeInsertAuthAuditLogAsync(
                    conn,
                    "SYSTEM-AUTH",
                    userEmail,
                    "REVOKED",
                    "Faculty Access Revoked",
                    User.Identity?.Name ?? "Admin"
                );

                _cache.Remove("approved_faculties");
                await SafeNotifyAcademicDataChangedAsync("faculty_revoked", null, userEmail);
                return Ok(new { status = "Success", message = "Faculty access revoked." });
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        private string NormalizeDept(string dept)
        {
            var d = (dept ?? "").ToLower().Trim();
            if (d == "it" || d == "bsit" || d.Contains("information technology")) return "it";
            if (d == "cpe" || d == "bscpe" || d.Contains("computer engineering")) return "cpe";
            if (d == "ece" || d == "bsece" || d.Contains("electrical engineering") || d.Contains("electronics")) return "ece";
            if (d == "ce" || d == "bsce" || d.Contains("civil engineering")) return "ce";
            if (d.Contains("accountancy")) return "acc";
            if (d.Contains("financial")) return "fm";
            if (d.Contains("marketing")) return "mm";
            if (d.Contains("human resource")) return "hrm";
            if (d.Contains("early childhood")) return "eced";
            if (d.Contains("english")) return "eng";
            if (d.Contains("filipino")) return "fil";
            if (d.Contains("mathematics")) return "math";
            if (d.Contains("science")) return "sci";
            if (d.Contains("social studies")) return "soc";
            if (d.Contains("physical education")) return "pe";
            if (d.Contains("communication")) return "comm";
            if (d.Contains("psychology")) return "psy";
            if (d.Contains("social work")) return "sw";
            if (d.Contains("public administration")) return "pa";
            return System.Text.RegularExpressions.Regex.Replace(d, "[^a-z0-9]", "");
        }

        [HttpGet("department/{email}/students/pending")]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> GetDepartmentPendingStudents(string email)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var cmdAdmin = new NpgsqlCommand("SELECT department FROM AdminProfiles ap JOIN Users u ON ap.user_id = u.id WHERE u.email = @email", conn);
                cmdAdmin.Parameters.AddWithValue("email", email);
                var adminDept = (string?)await cmdAdmin.ExecuteScalarAsync();

                if (string.IsNullOrEmpty(adminDept) || adminDept == "Unassigned") 
                    return BadRequest(new { status = "Error", message = "Admin is not assigned to a department." });

                var students = new List<object>();
                using var cmd = new NpgsqlCommand(@"
                    SELECT u.id, sp.full_name, u.email, sp.student_no, sp.section, sp.department
                    FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id
                    WHERE u.role = 'student' AND sp.assignment_status = 'Pending Department Approval'", conn);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var stuDept = reader.IsDBNull(5) ? "" : reader.GetString(5);
                    
                    if (NormalizeDept(stuDept) == NormalizeDept(adminDept))
                    {
                        students.Add(new {
                            id = reader.GetInt32(0),
                            fullname = reader.GetString(1),
                            email = reader.GetString(2),
                            studentno = reader.IsDBNull(3) ? null : reader.GetString(3),
                            section = reader.IsDBNull(4) ? null : reader.GetString(4)
                        });
                    }
                }
                return Ok(new { status = "Success", students });
            } 
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("faculty/{email}/assigned-sections")]
        [Authorize(Roles = "faculty,department_admin,registrar")]
        public async Task<IActionResult> GetFacultySections(string email)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var sections = new List<object>();
                using var cmd = new NpgsqlCommand(@"
                    SELECT fs.department, fs.section, fs.year_level, fs.subject 
                    FROM FacultySections fs 
                    JOIN Users u ON fs.user_id = u.id 
                    WHERE LOWER(u.email) = LOWER(@email) AND u.status = 'APPROVED'
                    ORDER BY fs.department, fs.year_level, fs.section", conn);
                
                cmd.Parameters.AddWithValue("email", email);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    sections.Add(new {
                        department = reader.GetString(0),
                        section = reader.GetString(1),
                        yearLevel = reader.IsDBNull(2) ? "N/A" : reader.GetString(2),
                        subject = reader.IsDBNull(3) ? "N/A" : reader.GetString(3)
                    });
                }

                return Ok(new { status = "Success", sections });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpDelete("faculty/{email}/assigned-sections")]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> UnassignFacultySection(string email, [FromQuery] string department, [FromQuery] string yearLevel, [FromQuery] string section, [FromQuery] string? subject)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var cmd = new NpgsqlCommand(@"
                    DELETE FROM FacultySections 
                    WHERE user_id = (SELECT id FROM Users WHERE LOWER(email) = LOWER(@email) LIMIT 1)
                    AND department = @dept AND year_level = @year AND section = @sec
                    AND (subject = @subj OR (subject IS NULL AND @subj IS NULL))", conn);
                
                cmd.Parameters.AddWithValue("email", email);
                cmd.Parameters.AddWithValue("dept", department);
                cmd.Parameters.AddWithValue("year", yearLevel);
                cmd.Parameters.AddWithValue("sec", section);
                cmd.Parameters.AddWithValue("subj", (object?)subject?.Trim() ?? DBNull.Value);

                await cmd.ExecuteNonQueryAsync();

                await NotifyAcademicDataChangedAsync("faculty_section_unassigned", department, email);
                return Ok(new { status = "Success", message = "Class unassigned successfully." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpGet("faculty/{email}/students")]
        [Authorize(Roles = "faculty,department_admin,registrar")]
        public async Task<IActionResult> GetFacultyStudents(string email)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                // Fetch all approved students matching ANY of the faculty's assigned sections across multiple departments
                var students = new List<object>();
                using var cmdStudents = new NpgsqlCommand(@"
                    SELECT DISTINCT u.id, sp.full_name, u.email, sp.student_no, sp.assignment_status, sp.department, sp.section, fs.section, fs.year_level
                    FROM Users u 
                    JOIN StudentProfiles sp ON u.id = sp.user_id
                    JOIN FacultySections fs ON LOWER(TRIM(sp.department)) = LOWER(TRIM(fs.department)) 
                      AND (LOWER(TRIM(sp.section)) = LOWER(TRIM(fs.section)) 
                        OR LOWER(TRIM(fs.section)) LIKE CONCAT('% ', LOWER(TRIM(sp.section)))
                        OR LOWER(TRIM(sp.section)) = LOWER(TRIM(CONCAT(fs.year_level, fs.section))) 
                        OR LOWER(TRIM(sp.section)) = LOWER(TRIM(CONCAT(fs.year_level, '-', fs.section))) 
                        OR LOWER(TRIM(sp.section)) = LOWER(TRIM(CONCAT(fs.department, '-', fs.year_level, fs.section))) 
                        OR LOWER(TRIM(sp.section)) = LOWER(TRIM(CONCAT(fs.department, fs.year_level, fs.section)))
                        OR LOWER(TRIM(sp.section)) = LOWER(TRIM(CONCAT(fs.department, '-', fs.section))))
                    JOIN Users fu ON fs.user_id = fu.id
                    WHERE u.role = 'student' AND u.status = 'APPROVED'
                      AND sp.assignment_status IN ('Enrolled', 'Pending Department Approval')
                      AND fu.email = @email AND fu.status = 'APPROVED'", conn);
                
                cmdStudents.Parameters.AddWithValue("email", email);

                using (var reader = await cmdStudents.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        students.Add(new {
                            id = reader.GetInt32(0),
                            fullname = reader.GetString(1),
                            email = reader.GetString(2),
                            studentno = reader.IsDBNull(3) ? "N/A" : reader.GetString(3),
                            enrollmentStatus = reader.IsDBNull(4) ? "Unassigned" : reader.GetString(4),
                            department = reader.IsDBNull(5) ? "N/A" : reader.GetString(5),
                            section = reader.IsDBNull(6) ? "N/A" : reader.GetString(6),
                            sectionNum = reader.IsDBNull(7) ? "N/A" : reader.GetString(7),
                            yearLevel = reader.IsDBNull(8) ? "N/A" : reader.GetString(8)
                        });
                    }
                }

                return Ok(new { status = "Success", students });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPut("students/{id}/approve-enrollment")]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> ApproveStudentEnrollment(int id)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                // Fetch user info for email notification
                string userEmail = "", userName = "Student", dept = "", section = "";
                using (var cmdEmail = new NpgsqlCommand("SELECT u.email, sp.full_name, sp.department, sp.section FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id WHERE u.id = @id", conn))
                {
                    cmdEmail.Parameters.AddWithValue("id", id); 
                    using var reader = await cmdEmail.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userEmail = reader.GetString(0);
                        userName = reader.GetString(1);
                        dept = reader.IsDBNull(2) ? "their department" : reader.GetString(2);
                        section = reader.IsDBNull(3) ? "" : reader.GetString(3);
                    }
                }

                string query = "UPDATE StudentProfiles SET assignment_status = 'Enrolled' WHERE user_id = @id";
                using var cmd = new NpgsqlCommand(query, conn);
                cmd.Parameters.AddWithValue("id", id);
                
                int rows = await cmd.ExecuteNonQueryAsync();
                if (rows == 0) return NotFound(new { status = "Error", message = "Student not found." });

                var emailSubject = "PLV Enrollment Officially Approved!";
                var emailContent = $"<p>Congratulations {userName}!</p><p>Your enrollment for <strong>{dept} - Section {section}</strong> has been officially approved by your Department Admin. Welcome!</p>";
                _ = _emailService.SendEmailAsync(userEmail, emailSubject, CreateHtmlEmail(emailSubject, emailContent), true);

                _cache.Remove("approved_students");

                await NotifyAcademicDataChangedAsync("student_enrollment_approved", dept, userEmail);
                return Ok(new { status = "Success", message = "Student officially enrolled in the department!" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost("students/bulk-upload")]
        [Authorize(Roles = "registrar")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> BulkUploadStudents(
            [FromForm] IFormFile file,
            [FromForm] string? defaultDepartment,
            [FromForm] string? mode,
            [FromForm] long? curriculumId = null,
            [FromForm] string? schoolYear = null,
            [FromForm] string? semester = null,
            [FromForm(Name = "yearLevel")] string? defaultYearLevel = null,
            [FromForm(Name = "section")] string? defaultSection = null)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { status = "Error", message = "A .csv or .xlsx file is required." });
            if (file.Length > 10 * 1024 * 1024)
                return BadRequest(new { status = "Error", message = "Student enrollment files cannot exceed 10 MB." });

            var normalizedMode = string.Equals(mode, "update", StringComparison.OrdinalIgnoreCase) ? "update" : "enroll";

            var ext = Path.GetExtension(file.FileName).ToLower();
            if (ext != ".csv" && ext != ".xlsx")
                return BadRequest(new { status = "Error", message = "Only .csv and .xlsx files are supported." });

            var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ext);
            var fallbackName = Path.GetFileNameWithoutExtension(file.FileName);
            bool isDepartmentFallback = fallbackName.StartsWith("Bachelor", StringComparison.OrdinalIgnoreCase) || 
                                        fallbackName.StartsWith("Master", StringComparison.OrdinalIgnoreCase) ||
                                        fallbackName.StartsWith("BS", StringComparison.OrdinalIgnoreCase);
            
            try
            {
                using (var fileStream = new FileStream(tempFile, FileMode.Create))
                    await file.CopyToAsync(fileStream);

                var parsedRecords = new List<Dictionary<string, string>>();
                var parsedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (ext == ".xlsx")
                {
                    using var workbook = new XLWorkbook(tempFile);
                    var ws = workbook.Worksheet(1);
                    var headerRow = ws.FirstRowUsed() ?? throw new ArgumentException("The enrollment file is empty.");
                    var headerMap = new Dictionary<string, int>();
                    foreach (var cell in headerRow.CellsUsed())
                    {
                        var heading = StudentEnrollmentFile.NormalizeHeader(cell.GetString());
                        if (heading.Length == 0 || !headerMap.TryAdd(heading, cell.Address.ColumnNumber))
                            throw new ArgumentException("Enrollment column headings must be non-empty and unique.");
                        parsedHeaders.Add(heading);
                    }
                    foreach (var row in ws.RowsUsed().Skip(1))
                        parsedRecords.Add(headerMap.ToDictionary(pair => pair.Key,
                            pair => row.Cell(pair.Value).Value.ToString().Trim()));
                }
                else
                {
                    using var reader = new StreamReader(tempFile, Encoding.UTF8);
                    (parsedHeaders, parsedRecords) = StudentEnrollmentFile.ReadCsv(reader);
                }
                if (parsedRecords.Count == 0) throw new ArgumentException("No student rows were found.");

                int successCount = 0;
                int failureCount = 0;
                var errors = new List<object>();

                using var httpClient = _httpClientFactory.CreateClient("FabricCAClient");
                var apiKey = Environment.GetEnvironmentVariable("INTERNAL_API_KEY") ?? _configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
                httpClient.DefaultRequestHeaders.Add("x-api-key", apiKey);
                var middlewareUrl = _configuration["Middleware:Url"] ?? _configuration["MIDDLEWARE_URL"] ?? "http://127.0.0.1:4000";

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                var seenStudentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                for (int index = 0; index < parsedRecords.Count; index++)
                {
                    var record = parsedRecords[index];
                    var rowNumber = index + 2;
                    string GetVal(params string[] keys)
                    {
                        foreach (var k in keys)
                        {
                            if (record.TryGetValue(k, out var val) && !string.IsNullOrWhiteSpace(val)) return val;
                        }
                        return "";
                    }

                    try
                    {
                        string studentNo = GetVal("student_id", "student_no", "student_number", "id_number");
                        string firstName = GetVal("first_name", "firstname", "given_name");
                        string lastName = GetVal("last_name", "lastname", "surname");
                        string middleName = GetVal("middle_name", "middlename", "middle");
                        string sex = GetVal("sex", "gender");
                        string email = GetVal("email", "email_address");
                        bool hasProvidedEmail = !string.IsNullOrWhiteSpace(email);
                        string phone = GetVal("number", "phone", "contact_number", "mobile_number");
                        string address = GetVal("address", "home_address");
                        string dobStr = GetVal("birthday", "dob", "date_of_birth");
                        string rowSection = GetVal("section", "class_section");
                        string dept = GetVal("department", "course", "program");
                        string rowYearLevel = GetVal("year_level", "year", "level");
                        string rowSchoolYear = GetVal("school_year", "academic_year");
                        string rowSemester = GetVal("semester", "term_semester");
                        string curriculumVersion = GetVal("curriculum_version", "curriculum", "curriculum_code");
                        
                        string name = GetVal("name", "full_name", "student_name");
                        if (string.IsNullOrEmpty(name)) {
                            name = $"{firstName} {middleName} {lastName}".Replace("  ", " ").Trim();
                        }

                        // A department-named file remains supported, but filenames are
                        // never treated as official section identifiers.
                        if (isDepartmentFallback) 
                        {
                            if (string.IsNullOrEmpty(dept)) dept = fallbackName;
                        }

                        if (string.IsNullOrEmpty(dept)) dept = defaultDepartment ?? "Unassigned";
                        if (string.IsNullOrWhiteSpace(rowSection)) rowSection = defaultSection ?? "";
                        // Serialize number allocation with enrollment writes, including explicit IDs.
                        using var tx = await conn.BeginTransactionAsync();
                        await using (var idLock = new NpgsqlCommand("SELECT pg_advisory_xact_lock(73120411)", conn, tx))
                            await idLock.ExecuteNonQueryAsync();
                        if (string.IsNullOrWhiteSpace(studentNo))
                        {
                            if (!hasProvidedEmail) throw new ArgumentException("Email is required when Student ID is blank.");
                            await using var existingNumber = new NpgsqlCommand(@"
                                SELECT sp.student_no FROM users u JOIN studentprofiles sp ON sp.user_id = u.id
                                WHERE LOWER(sp.student_email) = LOWER(@email) OR LOWER(u.email) = LOWER(@email);", conn, tx);
                            existingNumber.Parameters.AddWithValue("email", email.Trim());
                            await using (var numberReader = await existingNumber.ExecuteReaderAsync())
                            {
                                if (await numberReader.ReadAsync()) studentNo = numberReader.GetString(0);
                                if (await numberReader.ReadAsync()) throw new ArgumentException("Email matches multiple students. Supply the Student ID.");
                            }
                            if (string.IsNullOrWhiteSpace(studentNo))
                            {
                                if (normalizedMode == "update") throw new ArgumentException("Student does not exist yet. Use Bulk Enroll first.");
                                var enrollmentYear = int.Parse(NormalizeSchoolYear(string.IsNullOrWhiteSpace(rowSchoolYear) ? schoolYear : rowSchoolYear)[..4]);
                                studentNo = await AllocateStudentNumberAsync(conn, tx, enrollmentYear);
                            }
                        }

                        string loginId = studentNo; 
                        if (string.IsNullOrEmpty(email)) email = $"{loginId}@plv.edu.ph";

                        email = email.Trim().ToLower();
                        loginId = loginId.Trim().ToLower();
                        dobStr = dobStr.Trim();
                        middleName = middleName.Trim();
                        sex = sex.Trim();
                        phone = phone.Trim();
                        address = address.Trim();
                        if (!System.Text.RegularExpressions.Regex.IsMatch(loginId, @"^\d{2,4}-\d{4,}$"))
                            throw new Exception("Invalid value in column 'student_id'. Use xx-xxxx or xxxx-xxxx.");
                        if (!seenStudentIds.Add(loginId)) throw new Exception("Duplicate student ID in the uploaded file.");

                        int existingUserId = 0;
                        string existingRole = "";
                        bool existingStudentProfile = false;
                        string existingStudentNo = "";

                        using var checkCmd = new NpgsqlCommand(@"
                            SELECT
                                u.id,
                                COALESCE(u.role, ''),
                                COALESCE(u.status, ''),
                                EXISTS (
                                    SELECT 1
                                    FROM StudentProfiles sp
                                    WHERE sp.user_id = u.id
                                ) AS has_profile,
                                COALESCE(existing_profile.student_no, '')
                            FROM Users u
                            LEFT JOIN StudentProfiles existing_profile ON existing_profile.user_id = u.id
                            WHERE LOWER(u.email) = LOWER(@email)
                               OR LOWER(u.email) = LOWER(@loginId)
                               OR LOWER(COALESCE(existing_profile.student_no, '')) = LOWER(@loginId)
                               OR LOWER(existing_profile.student_email) = LOWER(@email)
                            LIMIT 1", conn, tx);
                        checkCmd.Parameters.AddWithValue("email", email);
                        checkCmd.Parameters.AddWithValue("loginId", loginId);
                        using (var existingReader = await checkCmd.ExecuteReaderAsync())
                        {
                            if (await existingReader.ReadAsync())
                            {
                                existingUserId = existingReader.GetInt32(0);
                                existingRole = existingReader.GetString(1);
                                _ = existingReader.GetString(2);
                                existingStudentProfile = !existingReader.IsDBNull(3) && existingReader.GetBoolean(3);
                                existingStudentNo = existingReader.IsDBNull(4) ? "" : existingReader.GetString(4).Trim();
                            }
                        }
                        bool exists = existingUserId > 0;

                        if (exists && !string.Equals(existingRole, "student", StringComparison.OrdinalIgnoreCase))
                            throw new Exception("That identifier belongs to a non-student account.");
                        if (exists && existingStudentProfile && !string.IsNullOrWhiteSpace(existingStudentNo) &&
                            !string.Equals(existingStudentNo, studentNo.Trim(), StringComparison.OrdinalIgnoreCase))
                            throw new Exception("Student ID cannot be changed after the student has been enrolled.");
                        if (!exists && normalizedMode == "update")
                            throw new Exception("Student does not exist yet. Use Bulk Enroll first.");
                        if (!exists && string.IsNullOrWhiteSpace(name))
                            throw new Exception("New students require name (or first and last name) columns.");

                        DateTime? dobDate = null;
                        if (!string.IsNullOrWhiteSpace(dobStr))
                        {
                            if (DateTime.TryParseExact(dobStr, "MM/dd/yyyy", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out DateTime parsedDob))
                                dobDate = parsedDob;
                            else if (DateTime.TryParse(dobStr, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out DateTime fallbackDob))
                                dobDate = fallbackDob;
                        }
                        if (!exists && !dobDate.HasValue)
                            throw new Exception("New students require a valid birthday using MM/DD/YYYY.");
                        var password = dobDate?.ToString("MM/dd/yyyy") ?? string.Empty;

                        var shouldSaveEnrollment = normalizedMode != "update" ||
                            !string.IsNullOrWhiteSpace(defaultDepartment) || !string.IsNullOrWhiteSpace(rowYearLevel) ||
                            !string.IsNullOrWhiteSpace(rowSchoolYear) || !string.IsNullOrWhiteSpace(rowSemester) ||
                            curriculumId.HasValue;
                        (int Id, string Code, string Name)? program = null;
                        long? resolvedCurriculumId = null;
                        short resolvedYearLevel = NormalizeYearLevel(
                            string.IsNullOrWhiteSpace(rowYearLevel) ? defaultYearLevel : rowYearLevel,
                            rowSection);
                        string resolvedSchoolYear = NormalizeSchoolYear(string.IsNullOrWhiteSpace(rowSchoolYear) ? schoolYear : rowSchoolYear);
                        string resolvedSemester = NormalizeEnrollmentSemester(string.IsNullOrWhiteSpace(rowSemester) ? semester : rowSemester);
                        if (shouldSaveEnrollment)
                        {
                            rowSection = StudentEnrollmentFile.ResolveSection(rowSection, GetVal("section_number", "section_num"), resolvedYearLevel);
                            program = await ResolveEnrollmentProgramAsync(conn, tx, dept);
                            resolvedCurriculumId = await ResolveEnrollmentCurriculumAsync(conn, tx, program.Value.Id, curriculumId, curriculumVersion);
                            dept = program.Value.Name;
                        }

                        var userId = existingUserId;

                        if (exists)
                        {
                            using var updateStatusCmd = new NpgsqlCommand("UPDATE Users SET status = 'APPROVED', is_active = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = @id RETURNING id", conn, tx);
                            updateStatusCmd.Parameters.AddWithValue("id", existingUserId);
                            userId = (int)(await updateStatusCmd.ExecuteScalarAsync() ?? 0);

                            if (userId > 0)
                            {
                                if (existingStudentProfile)
                                {
                                    using var updateProfile = new NpgsqlCommand(@"
                                        UPDATE StudentProfiles 
                                        SET full_name = COALESCE(@name, full_name),
                                            student_no = CASE
                                                WHEN NULLIF(BTRIM(student_no), '') IS NULL THEN @studentno
                                                ELSE student_no
                                            END,
                                            department = COALESCE(@dept, department),
                                            section = COALESCE(@sec, section),
                                            date_of_birth = COALESCE(@dob, date_of_birth),
                                            student_email = COALESCE(@studentEmail, student_email),
                                            middle_name = COALESCE(@middleName, middle_name),
                                            sex = COALESCE(@sex, sex),
                                            phone = COALESCE(@phone, phone),
                                            address = COALESCE(@address, address),
                                             year_level = COALESCE(@yearLevel, year_level),
                                             curriculum_id = COALESCE(@curriculumId, curriculum_id),
                                             assignment_status = CASE WHEN @saveEnrollment THEN 'Enrolled' ELSE assignment_status END
                                        WHERE user_id = @uid", conn, tx);
                                    updateProfile.Parameters.AddWithValue("name", !string.IsNullOrEmpty(name) ? (object)name : DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("studentno", !string.IsNullOrEmpty(studentNo) ? (object)studentNo : DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("dept", shouldSaveEnrollment ? dept : DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("sec", string.IsNullOrEmpty(rowSection) ? DBNull.Value : (object)rowSection);
                                    updateProfile.Parameters.AddWithValue("dob", dobDate.HasValue ? (object)dobDate.Value.Date : DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("studentEmail", hasProvidedEmail ? (object)email : DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("middleName", string.IsNullOrEmpty(middleName) ? DBNull.Value : (object)middleName);
                                    updateProfile.Parameters.AddWithValue("sex", string.IsNullOrEmpty(sex) ? DBNull.Value : (object)sex);
                                    updateProfile.Parameters.AddWithValue("phone", string.IsNullOrEmpty(phone) ? DBNull.Value : (object)phone);
                                    updateProfile.Parameters.AddWithValue("address", string.IsNullOrEmpty(address) ? DBNull.Value : (object)address);
                                    updateProfile.Parameters.AddWithValue("yearLevel", shouldSaveEnrollment ? (object)resolvedYearLevel.ToString() : DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("curriculumId", (object?)resolvedCurriculumId ?? DBNull.Value);
                                    updateProfile.Parameters.AddWithValue("saveEnrollment", shouldSaveEnrollment);
                                    updateProfile.Parameters.AddWithValue("uid", userId);
                                    await updateProfile.ExecuteNonQueryAsync();
                                }
                                else
                                {
                                    using var insertProfile = new NpgsqlCommand(@"
                                        INSERT INTO StudentProfiles (user_id, full_name, student_no, department, section, year_level, curriculum_id, date_of_birth, student_email, middle_name, sex, phone, address, assignment_status)
                                        VALUES (@uid, @name, @studentno, @dept, @sec, @yearLevel, @curriculumId, @dob, @studentEmail, @middleName, @sex, @phone, @address,
                                                CASE WHEN @saveEnrollment THEN 'Enrolled' ELSE 'Unassigned' END)", conn, tx);
                                    insertProfile.Parameters.AddWithValue("uid", userId);
                                    insertProfile.Parameters.AddWithValue("name", !string.IsNullOrEmpty(name) ? (object)name : DBNull.Value);
                                    insertProfile.Parameters.AddWithValue("studentno", !string.IsNullOrEmpty(studentNo) ? (object)studentNo : DBNull.Value);
                                    insertProfile.Parameters.AddWithValue("dept", !string.IsNullOrEmpty(dept) ? (object)dept : DBNull.Value);
                                    insertProfile.Parameters.AddWithValue("sec", string.IsNullOrEmpty(rowSection) ? DBNull.Value : (object)rowSection);
                                    insertProfile.Parameters.AddWithValue("dob", dobDate.HasValue ? (object)dobDate.Value.Date : DBNull.Value);
                                    insertProfile.Parameters.AddWithValue("studentEmail", string.IsNullOrEmpty(email) ? DBNull.Value : (object)email);
                                    insertProfile.Parameters.AddWithValue("middleName", string.IsNullOrEmpty(middleName) ? DBNull.Value : (object)middleName);
                                    insertProfile.Parameters.AddWithValue("sex", string.IsNullOrEmpty(sex) ? DBNull.Value : (object)sex);
                                    insertProfile.Parameters.AddWithValue("phone", string.IsNullOrEmpty(phone) ? DBNull.Value : (object)phone);
                                    insertProfile.Parameters.AddWithValue("address", string.IsNullOrEmpty(address) ? DBNull.Value : (object)address);
                                    insertProfile.Parameters.AddWithValue("yearLevel", shouldSaveEnrollment ? (object)resolvedYearLevel.ToString() : DBNull.Value);
                                    insertProfile.Parameters.AddWithValue("curriculumId", (object?)resolvedCurriculumId ?? DBNull.Value);
                                    insertProfile.Parameters.AddWithValue("saveEnrollment", shouldSaveEnrollment);
                                    await insertProfile.ExecuteNonQueryAsync();
                                }
                            }
                        }
                        else
                        {
                            using var cmdUser = new NpgsqlCommand("INSERT INTO Users (username, email, password_hash, role, status, is_active) VALUES (@username, @email, crypt(@password, gen_salt('bf', 12)), 'student', 'APPROVED', TRUE) RETURNING id", conn, tx);
                            cmdUser.Parameters.AddWithValue("username", loginId);
                            cmdUser.Parameters.AddWithValue("email", loginId);
                            cmdUser.Parameters.AddWithValue("password", password);
                            userId = (int)(await cmdUser.ExecuteScalarAsync() ?? throw new Exception("Failed to retrieve new User ID"));

                            using var cmdProfile = new NpgsqlCommand(@"
                                INSERT INTO StudentProfiles (user_id, full_name, student_no, department, section, year_level, curriculum_id, date_of_birth, student_email, middle_name, sex, phone, address, assignment_status)
                                VALUES (@uid, @name, @studentno, @dept, @sec, @yearLevel, @curriculumId, @dob, @studentEmail, @middleName, @sex, @phone, @address, 'Enrolled')", conn, tx);
                            cmdProfile.Parameters.AddWithValue("uid", userId);
                            cmdProfile.Parameters.AddWithValue("name", !string.IsNullOrEmpty(name) ? (object)name : DBNull.Value);
                            cmdProfile.Parameters.AddWithValue("studentno", !string.IsNullOrEmpty(studentNo) ? (object)studentNo : DBNull.Value);
                            cmdProfile.Parameters.AddWithValue("dept", !string.IsNullOrEmpty(dept) ? (object)dept : DBNull.Value);
                            cmdProfile.Parameters.AddWithValue("sec", string.IsNullOrEmpty(rowSection) ? DBNull.Value : (object)rowSection);
                            cmdProfile.Parameters.AddWithValue("dob", dobDate.HasValue ? (object)dobDate.Value.Date : DBNull.Value);
                            cmdProfile.Parameters.AddWithValue("studentEmail", string.IsNullOrEmpty(email) ? DBNull.Value : (object)email);
                            cmdProfile.Parameters.AddWithValue("middleName", string.IsNullOrEmpty(middleName) ? DBNull.Value : (object)middleName);
                            cmdProfile.Parameters.AddWithValue("sex", string.IsNullOrEmpty(sex) ? DBNull.Value : (object)sex);
                            cmdProfile.Parameters.AddWithValue("phone", string.IsNullOrEmpty(phone) ? DBNull.Value : (object)phone);
                            cmdProfile.Parameters.AddWithValue("address", string.IsNullOrEmpty(address) ? DBNull.Value : (object)address);
                            cmdProfile.Parameters.AddWithValue("yearLevel", resolvedYearLevel.ToString());
                            cmdProfile.Parameters.AddWithValue("curriculumId", (object?)resolvedCurriculumId ?? DBNull.Value);
                            await cmdProfile.ExecuteNonQueryAsync();
                        }

                        if (shouldSaveEnrollment && program.HasValue)
                        {
                            var academicSectionId = await EnsureEnrollmentSectionAsync(conn, tx, program.Value.Name, resolvedYearLevel, rowSection);
                            await UpsertStudentEnrollmentAsync(conn, tx, userId, studentNo, program.Value.Id, resolvedCurriculumId,
                                academicSectionId, resolvedSchoolYear, resolvedSemester, resolvedYearLevel, rowSection,
                                User.Identity?.Name ?? "registrar");
                        }

                        if (!exists)
                        {
                            var payload = new { email = loginId, role = "student", password = password };
                            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                            var fabResponse = await httpClient.PostAsync($"{middlewareUrl}/api/fabric/register-user", content);
                            
                            if (!fabResponse.IsSuccessStatusCode)
                            {
                                string errBody = await fabResponse.Content.ReadAsStringAsync();
                                throw new Exception($"Blockchain wallet registration failed: {errBody}");
                            }
                        }

                        await _auditLog.LogAsync(User.Identity?.Name ?? "registrar", "registrar",
                            normalizedMode == "update" ? "STUDENT_PROFILE_UPDATED" : "STUDENT_ENROLLED",
                            shouldSaveEnrollment ? "student_enrollment" : "student", userId.ToString(), null,
                            new { studentNo, program = program?.Code, curriculumId = resolvedCurriculumId, schoolYear = resolvedSchoolYear, semester = resolvedSemester, yearLevel = resolvedYearLevel, section = rowSection },
                            normalizedMode == "update" ? "Registrar updated a student record by administrative upload." : "Registrar enrolled a student by administrative upload.",
                            HttpContext.Connection.RemoteIpAddress?.ToString(), conn, tx);
                        await tx.CommitAsync();

                        successCount++;
                    }
                    catch (Exception rowEx)
                    {
                        failureCount++;
                        var studentIdVal = GetVal("student_id", "student_no", "student_number", "id_number");
                        errors.Add(new
                        {
                            row = rowNumber,
                            identifier = !string.IsNullOrWhiteSpace(studentIdVal) ? studentIdVal : "Unknown",
                            reason = rowEx.Message
                        });
                    }
                }

                // Invalidate Caches so UI immediately shows new students
                _cache.Remove("approved_students");
                _cache.Remove("pending_requests");

                await NotifyAcademicDataChangedAsync("students_bulk_uploaded", defaultDepartment, User.Identity?.Name);
                return Ok(new
                {
                    status = failureCount == 0 ? "Success" : "Partial Success",
                    totalProcessed = successCount + failureCount,
                    successful = successCount,
                    failed = failureCount,
                    errors = errors.Any() ? errors : null,
                    message = normalizedMode == "update"
                        ? (failureCount > 0
                            ? $"{successCount} student record(s) updated successfully. {failureCount} row(s) need attention."
                            : $"{successCount} student record(s) updated successfully.")
                        : (failureCount > 0
                            ? $"{successCount} students automatically enrolled and approved. {failureCount} row(s) need attention."
                            : $"{successCount} students automatically enrolled and approved.")
                });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
            catch (CsvHelper.CsvHelperException)
            {
                return BadRequest(new { status = "Error", message = "Invalid enrollment CSV. Check headings and quote values containing commas." });
            }
            finally
            {
                if (System.IO.File.Exists(tempFile))
                    System.IO.File.Delete(tempFile);
            }
        }

        private string? ResolveEmailLogoPath()
        {
            var configuredPath =
                _configuration["Email:LogoPath"] ??
                _configuration["Smtp:LogoPath"] ??
                _configuration["PlvLogoPath"];

            var candidates = new[]
            {
                configuredPath,
                Path.Combine(Directory.GetCurrentDirectory(), "plvlogo.png"),
                Path.Combine(Directory.GetCurrentDirectory(), "assets", "plvlogo.png"),
                Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "plvlogo.png"),
                Path.Combine(Directory.GetCurrentDirectory(), "frontend", "plvlogo.png"),
                Path.Combine(Directory.GetCurrentDirectory(), "frontend", "public", "plvlogo.png"),
                Path.Combine(Directory.GetCurrentDirectory(), "frontend", "src", "assets", "plvlogo.png"),
                Path.Combine(Directory.GetCurrentDirectory(), "..", "frontend", "src", "assets", "plvlogo.png"),
                Path.Combine(AppContext.BaseDirectory, "assets", "plvlogo.png"),
                Path.Combine(AppContext.BaseDirectory, "plvlogo.png"),
                Path.Combine(AppContext.BaseDirectory, "..", "assets", "plvlogo.png"),
                Path.Combine(AppContext.BaseDirectory, "..", "frontend", "src", "assets", "plvlogo.png"),
                Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "frontend", "src", "assets", "plvlogo.png"),
                Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "client-app", "assets", "plvlogo.png")
            };

            foreach (var candidate in candidates.Where(c => !string.IsNullOrWhiteSpace(c)))
            {
                try
                {
                    var fullPath = Path.GetFullPath(candidate!);
                    if (System.IO.File.Exists(fullPath) && new FileInfo(fullPath).Length > 0) return fullPath;
                }
                catch
                {
                    // Ignore malformed configured paths and continue through the known locations.
                }
            }

            return null;
        }

        private string CreateHtmlEmail(string subject, string content, bool useInlineLogo = false)
        {
            var year = DateTime.UtcNow.Year;
            var imagePath = ResolveEmailLogoPath();
            string logoSrc;
            
            if (useInlineLogo && imagePath != null)
            {
                logoSrc = $"cid:{EmailLogoContentId}";
            }
            else if (imagePath != null)
            {
                byte[] imageBytes = System.IO.File.ReadAllBytes(imagePath);
                logoSrc = $"data:image/png;base64,{Convert.ToBase64String(imageBytes)}";
            }
            else
            {
                logoSrc = "https://upload.wikimedia.org/wikipedia/en/5/52/Pamantasan_ng_Lungsod_ng_Valenzuela_logo.png";
            }

            return $@"
            <!DOCTYPE html>
            <html lang='en'>
            <head><meta charset='UTF-8'></head>
            <body style='font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;'>
                <div style='max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                    <div style='text-align: center; padding-bottom: 20px; border-bottom: 1px solid #ddd;'>
                        <img src='{logoSrc}' alt='PLV Logo' style='max-width: 100px;'>
                        <h2 style='margin: 10px 0 0 0; color: #003366;'>Pamantasan ng Lungsod ng Valenzuela</h2>
                    </div>
                    <div style='padding: 20px 0; line-height: 1.6; color: #333;'>
                        <h3 style='color: #003366;'>{subject}</h3>
                        {content.Replace("\n", "<br />")}
                    </div>
                    <div style='text-align: center; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #777;'>
                        <p>&copy; {year} PLV BlockGO. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>";
        }

        [HttpGet("user-profile")]
        public async Task<IActionResult> GetUserProfile([FromQuery] string email, [FromQuery] string role)
        {
            try
            {
                var authenticatedEmail = User.Identity?.Name;
                var authenticatedRole = NormalizeSystemRole(User.FindFirst("dbRole")?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value);
                if (string.IsNullOrWhiteSpace(authenticatedEmail)) return Unauthorized();
                if (!string.Equals(email, authenticatedEmail, StringComparison.OrdinalIgnoreCase)) return Forbid();
                email = authenticatedEmail;

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                var normalizedRole = authenticatedRole;

                string query = "";
                NpgsqlCommand cmd;
                UserProfileDto? userProfile = null;

                // Base query to get user info
                string baseQuery = "SELECT u.id, u.email, u.role, u.status, ";

                if (normalizedRole == "student")
                {
                    query = baseQuery + @"sp.full_name, sp.department, sp.student_no, sp.section,
                        sp.date_of_birth, sp.student_email, sp.middle_name, sp.phone, sp.address, sp.sex,
                        COALESCE(sp.year_level, enrollment.year_level::text),
                        COALESCE(sp.curriculum_id, enrollment.curriculum_id),
                        curriculum.curriculum_name, curriculum.curriculum_version,
                        enrollment.school_year, enrollment.semester, enrollment.status
                        FROM Users u
                        JOIN StudentProfiles sp ON u.id = sp.user_id
                        LEFT JOIN LATERAL (
                            SELECT se.curriculum_id, se.year_level, se.school_year, se.semester, se.status
                            FROM student_enrollments se
                            WHERE se.student_user_id = u.id
                            ORDER BY se.updated_at DESC, se.enrollment_id DESC
                            LIMIT 1
                        ) enrollment ON TRUE
                        LEFT JOIN curriculums curriculum
                          ON curriculum.curriculum_id = COALESCE(sp.curriculum_id, enrollment.curriculum_id)
                        WHERE LOWER(u.email) = LOWER(@email)";
                    cmd = new NpgsqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("email", email);
                    using var reader = await cmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userProfile = new UserProfileDto
                        {
                            Id = reader.GetInt32(0),
                            Email = reader.GetString(1),
                            Role = NormalizeSystemRole(reader.GetString(2)),
                            Status = reader.GetString(3),
                            FullName = reader.GetString(4),
                            Department = reader.IsDBNull(5) ? null : reader.GetString(5),
                            StudentNo = reader.IsDBNull(6) ? null : reader.GetString(6),
                            Section = reader.IsDBNull(7) ? null : reader.GetString(7),
                            DateOfBirth = reader.IsDBNull(8) ? null : reader.GetDateTime(8).ToString("MM/dd/yyyy"),
                            StudentEmail = reader.IsDBNull(9) ? null : reader.GetString(9),
                            MiddleName = reader.IsDBNull(10) ? null : reader.GetString(10),
                            Phone = reader.IsDBNull(11) ? null : reader.GetString(11),
                            Address = reader.IsDBNull(12) ? null : reader.GetString(12),
                            Sex = reader.IsDBNull(13) ? null : reader.GetString(13),
                            YearLevel = reader.IsDBNull(14) ? null : reader.GetString(14),
                            CurriculumId = reader.IsDBNull(15) ? null : reader.GetInt64(15),
                            CurriculumName = reader.IsDBNull(16) ? null : reader.GetString(16),
                            CurriculumVersion = reader.IsDBNull(17) ? null : reader.GetString(17),
                            SchoolYear = reader.IsDBNull(18) ? null : reader.GetString(18),
                            Semester = reader.IsDBNull(19) ? null : reader.GetString(19),
                            EnrollmentStatus = reader.IsDBNull(20) ? null : reader.GetString(20)
                        };
                    }
                }
                else if (normalizedRole == "faculty")
                {
                    query = baseQuery + "fp.full_name, fp.department, fp.section, fp.year_level, fp.faculty_type FROM Users u JOIN FacultyProfiles fp ON u.id = fp.user_id WHERE u.email = @email";
                    cmd = new NpgsqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("email", email);
                    using var reader = await cmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userProfile = new UserProfileDto
                        {
                            Id = reader.GetInt32(0),
                            Email = reader.GetString(1),
                            Role = NormalizeSystemRole(reader.GetString(2)),
                            Status = reader.GetString(3),
                            FullName = reader.GetString(4),
                            Department = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Section = reader.IsDBNull(6) ? null : reader.GetString(6),
                            YearLevel = reader.IsDBNull(7) ? null : reader.GetString(7),
                            FacultyType = reader.IsDBNull(8) ? null : reader.GetString(8)
                        };
                    }
                }
                else if (normalizedRole == "registrar" || normalizedRole == "department_admin" || normalizedRole == "system_admin")
                {
                    query = baseQuery + "ap.full_name, ap.department FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id WHERE u.email = @email";
                    cmd = new NpgsqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("email", email);
                    using var reader = await cmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        userProfile = new UserProfileDto
                        {
                            Id = reader.GetInt32(0),
                            Email = reader.GetString(1),
                            Role = NormalizeSystemRole(reader.GetString(2)),
                            Status = reader.GetString(3),
                            FullName = reader.GetString(4),
                            Department = reader.IsDBNull(5) ? null : reader.GetString(5)
                        };
                    }
                }
                else
                {
                    return BadRequest(new { status = "Error", message = "Invalid role specified." });
                }

                if (userProfile == null)
                {
                    return NotFound(new { status = "Error", message = "User profile not found." });
                }

                // NEW: If student, fetch their enrolled subjects from FacultySections
                if (normalizedRole == "student" && !string.IsNullOrEmpty(userProfile.Section))
                {
                    try
                    {
                        var subjects = new List<string>();
                        using var cmdSub = new NpgsqlCommand(@"
                            SELECT DISTINCT subject 
                            FROM FacultySections 
                            WHERE LOWER(TRIM(department)) = LOWER(TRIM(@dept)) 
                            AND (LOWER(TRIM(section)) = LOWER(TRIM(@sec))
                                 OR LOWER(TRIM(CONCAT(year_level, section))) = LOWER(TRIM(@sec))
                                 OR LOWER(TRIM(CONCAT(year_level, '-', section))) = LOWER(TRIM(@sec)))
                            AND subject IS NOT NULL", conn);
                        cmdSub.Parameters.AddWithValue("dept", userProfile.Department ?? "");
                        cmdSub.Parameters.AddWithValue("sec", userProfile.Section);

                        using var readerSub = await cmdSub.ExecuteReaderAsync();
                        while (await readerSub.ReadAsync())
                        {
                            subjects.Add(readerSub.GetString(0));
                        }
                        userProfile.EnrolledSubjects = subjects;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Failed to fetch enrolled subjects: {Message}", ex.Message);
                    }
                }

                return Ok(new { status = "Success", data = userProfile });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [HttpPost("bulk-masterlist")]
        [Authorize(Roles = "registrar")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> BulkMasterlistUpload([FromForm] IFormFile file, [FromForm] string department)
        {
            if (file == null || file.Length == 0) return BadRequest(new { status = "Error", message = "A .csv or .xlsx file is required." });
            
            var ext = Path.GetExtension(file.FileName).ToLower();
            if (ext != ".csv" && ext != ".xlsx") return BadRequest(new { status = "Error", message = "Only .csv and .xlsx files are supported." });

            var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ext);
            try
            {
                using (var fileStream = new FileStream(tempFile, FileMode.Create)) await file.CopyToAsync(fileStream);
                var parsedRecords = new List<Dictionary<string, string>>();
                
                string NormalizeHeader(string s) => System.Text.RegularExpressions.Regex.Replace(s.Trim().ToLower(), @"[^a-z0-9]+", "_").Trim('_');

                if (ext == ".xlsx")
                {
                    using var workbook = new XLWorkbook(tempFile);
                    var ws = workbook.Worksheet(1);
                    var headerRow = ws.FirstRowUsed();
                    var headerMap = new Dictionary<string, int>();
                    if (headerRow != null)
                    {
                        foreach (var cell in headerRow.CellsUsed())
                        {
                            var normalized = NormalizeHeader(cell.Value.ToString() ?? "");
                            if (!string.IsNullOrEmpty(normalized)) headerMap[normalized] = cell.Address.ColumnNumber;
                        }

                        var rows = ws.RowsUsed().Skip(1);
                        foreach (var row in rows)
                        {
                            var dict = new Dictionary<string, string>();
                            foreach (var kvp in headerMap) dict[kvp.Key] = row.Cell(kvp.Value).Value.ToString().Trim();
                            parsedRecords.Add(dict);
                        }
                    }
                }
                else if (ext == ".csv")
                {
                    using var reader = new StreamReader(tempFile, Encoding.UTF8);
                    string? line; int lineNum = 0; Dictionary<string, int>? headerMap = null;
                    while ((line = await reader.ReadLineAsync()) != null)
                    {
                        lineNum++; line = line.Trim(); if (string.IsNullOrEmpty(line)) continue;
                        
                        // Robust CSV splitting (supports comma, semicolon, and tab)
                        string[] fields;
                        if (line.Contains('\t')) fields = line.Split('\t');
                        else if (line.Contains(';')) fields = line.Split(';');
                        else fields = line.Split(',');

                        if (lineNum == 1) 
                        { 
                            headerMap = new Dictionary<string, int>(); 
                            for (int i = 0; i < fields.Length; i++)
                            {
                                var normalized = NormalizeHeader(fields[i]);
                                if (!string.IsNullOrEmpty(normalized)) headerMap[normalized] = i;
                            }
                            continue; 
                        }

                        var dict = new Dictionary<string, string>();
                        if (headerMap != null) {
                            foreach (var kvp in headerMap)
                                if (kvp.Value < fields.Length) dict[kvp.Key] = fields[kvp.Value].Trim().Trim('"');
                        }
                        parsedRecords.Add(dict);
                    }
                }

                if (parsedRecords.Count == 0)
                {
                    return BadRequest(new { status = "Error", message = "No data records found in the uploaded file. Please check the file format and headers." });
                }

                int successCount = 0;
                int failureCount = 0;
                int skippedCount = 0;
                var errors = new List<object>();

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                var canonicalProgram = await ResolveEnrollmentProgramAsync(conn, null, department);
                department = canonicalProgram.Name;

                foreach (var record in parsedRecords)
                {
                    string GetVal(params string[] keys)
                    {
                        foreach (var k in keys) if (record.TryGetValue(k, out var val) && !string.IsNullOrWhiteSpace(val)) return val;
                        return "";
                    }

                    try 
                    {
                        string studentNo = GetVal("student_no", "student_number", "id_number", "student_id", "id", "student_no_", "id_no");
                        string yearLevel = GetVal("year_level", "year", "level", "yr_lvl", "year_lvl");
                        string section = GetVal("section", "class_section", "sec", "section_num");
                        string subjectCode = GetVal("subject_code", "course_code", "subject", "course", "subj_code", "subj");
                        string facultyName = GetVal("faculty_name", "professor", "instructor", "faculty", "teacher", "prof_name", "prof");
                        string facultyEmail = GetVal("faculty_email", "prof_email", "email", "instructor_email", "prof_email_address");

                        if (string.IsNullOrEmpty(studentNo) || string.IsNullOrEmpty(facultyName) || string.IsNullOrEmpty(subjectCode))
                        {
                            skippedCount++;
                            _logger.LogWarning("Skipping row in Masterlist: Missing StudentNo({S}), Faculty({F}), or Subject({Sub})", 
                                !string.IsNullOrEmpty(studentNo), !string.IsNullOrEmpty(facultyName), !string.IsNullOrEmpty(subjectCode));
                            continue;
                        }
                        if (!int.TryParse(yearLevel, out var parsedYearLevel) || parsedYearLevel < 1 || parsedYearLevel > 4)
                            throw new Exception("Year level must be a number from 1 to 4.");
                        if (!int.TryParse(section, out var parsedSectionNumber) || parsedSectionNumber < 1)
                            throw new Exception("Section must be a positive number.");

                        string profLoginId = !string.IsNullOrWhiteSpace(facultyEmail) ? facultyEmail : facultyName;
                        string studentLoginId = studentNo.Trim(); 

                        using var tx = await conn.BeginTransactionAsync();

                        // Account creation is intentionally not duplicated here.
                        // Faculty and students must exist through the Registrar's
                        // managed account/enrollment workflows before mapping.
                        int facultyUserId = 0;
                        using (var checkFac = new NpgsqlCommand(@"
                            SELECT id FROM Users
                            WHERE LOWER(email) = LOWER(@email) AND LOWER(role) = 'faculty'
                              AND LOWER(status) = 'approved' AND is_active = TRUE", conn, tx))
                        {
                            checkFac.Parameters.AddWithValue("email", profLoginId);
                            var fIdObj = await checkFac.ExecuteScalarAsync();
                            if (fIdObj != null && fIdObj != DBNull.Value) facultyUserId = Convert.ToInt32(fIdObj);
                        }

                        if (facultyUserId == 0)
                            throw new Exception($"Faculty account '{profLoginId}' must be created and approved before masterlist mapping.");

                        // 2. Create Section Mapping
                        string fullSection = $"{yearLevel}-{section}";
                        using var cmdSec = new NpgsqlCommand("INSERT INTO AcademicSections (department, year_level, section_num) VALUES (@dept, @year, @sec) ON CONFLICT DO NOTHING", conn, tx);
                        cmdSec.Parameters.AddWithValue("dept", department);
                        cmdSec.Parameters.AddWithValue("year", parsedYearLevel);
                        cmdSec.Parameters.AddWithValue("sec", parsedSectionNumber);
                        await cmdSec.ExecuteNonQueryAsync();

                        // Assign Section To Faculty
                        using var cmdAssign = new NpgsqlCommand(@"
                            INSERT INTO FacultySections (user_id, department, section, year_level, subject) 
                            VALUES (@uid, @dept, @sec, @year, @subj) 
                            ON CONFLICT (user_id, department, section, subject) DO NOTHING", conn, tx);
                        cmdAssign.Parameters.AddWithValue("uid", facultyUserId);
                        cmdAssign.Parameters.AddWithValue("dept", department);
                        cmdAssign.Parameters.AddWithValue("sec", section);
                        cmdAssign.Parameters.AddWithValue("year", yearLevel);
                        cmdAssign.Parameters.AddWithValue("subj", subjectCode);
                        await cmdAssign.ExecuteNonQueryAsync();

                        // 3. Resolve an officially enrolled Student
                        int studentUserId = 0;
                        using (var checkStu = new NpgsqlCommand(@"
                            SELECT u.id
                            FROM Users u
                            LEFT JOIN StudentProfiles sp ON sp.user_id = u.id
                            WHERE LOWER(u.role) = 'student' AND LOWER(u.status) = 'approved' AND u.is_active = TRUE
                              AND (LOWER(u.email) = LOWER(@studentNo)
                                   OR LOWER(COALESCE(u.username, '')) = LOWER(@studentNo)
                                   OR LOWER(COALESCE(sp.student_no, '')) = LOWER(@studentNo))
                            LIMIT 1", conn, tx))
                        {
                            checkStu.Parameters.AddWithValue("studentNo", studentLoginId);
                            var sIdObj = await checkStu.ExecuteScalarAsync();
                            if (sIdObj != null && sIdObj != DBNull.Value) studentUserId = Convert.ToInt32(sIdObj);
                        }

                        if (studentUserId == 0)
                            throw new Exception($"Student '{studentLoginId}' must be enrolled before masterlist mapping.");

                        using var updateProfile = new NpgsqlCommand(@"
                            UPDATE StudentProfiles
                            SET department = @dept, section = @sec, year_level = @year, assignment_status = 'Enrolled'
                            WHERE user_id = @uid", conn, tx);
                        updateProfile.Parameters.AddWithValue("dept", department);
                        updateProfile.Parameters.AddWithValue("sec", fullSection);
                        updateProfile.Parameters.AddWithValue("year", yearLevel);
                        updateProfile.Parameters.AddWithValue("uid", studentUserId);
                        await updateProfile.ExecuteNonQueryAsync();

                        await tx.CommitAsync();
                        successCount++;
                    }
                    catch (Exception ex)
                    {
                        failureCount++;
                        errors.Add(new { identifier = GetVal("student_no"), reason = ex.Message });
                        _logger.LogError(ex, "Error processing Masterlist row for student {S}", GetVal("student_no"));
                    }
                }

                try {
                    using var cmdChair = new NpgsqlCommand("SELECT u.email FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id WHERE ap.department = @dept AND LOWER(REPLACE(REPLACE(u.role, ' ', '_'), '-', '_')) IN ('department_admin', 'dept_admin', 'deptadmin', 'department', 'admin', 'chairperson') AND u.status = 'APPROVED' LIMIT 1", conn);
                    cmdChair.Parameters.AddWithValue("dept", department);
                    var chairEmail = (await cmdChair.ExecuteScalarAsync()) as string;
                    
                    if (!string.IsNullOrEmpty(chairEmail)) {
                        var subject = "PLV System: New Student Masterlist Uploaded";
                        var content = $"<p>Hello,</p><p>A new student masterlist for the <strong>{department}</strong> department has been successfully uploaded and processed. Please log in to the Chairperson portal to review the auto-generated sections and student assignments.</p>";
                        _ = _emailService.SendEmailAsync(chairEmail, subject, CreateHtmlEmail(subject, content), true);
                    }
                } catch (Exception notifyEx) { _logger.LogWarning(notifyEx, "Could not notify chairperson of masterlist upload"); }

                _cache.Remove("approved_students");
                await NotifyAcademicDataChangedAsync("masterlist_uploaded", department, User.Identity?.Name);
                return Ok(new { 
                    status = (successCount > 0 && failureCount == 0) ? "Success" : (successCount > 0 ? "Partial Success" : "Error"), 
                    totalProcessed = parsedRecords.Count,
                    successful = successCount,
                    failed = failureCount,
                    skipped = skippedCount,
                    message = successCount > 0 ? $"Processed Masterlist: {successCount} mapped successfully." : "No records were successfully mapped. Please verify the file headers.",
                    errors = errors.Any() ? errors : null
                });

            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
            finally { if (System.IO.File.Exists(tempFile)) System.IO.File.Delete(tempFile); }
        }

        public class CreateSectionRequest
        {
            [JsonPropertyName("department")]
            public string Department { get; set; } = string.Empty;
            [JsonPropertyName("yearLevel")]
            public string YearLevel { get; set; } = string.Empty;
            [JsonPropertyName("sectionNum")]
            public string SectionNum { get; set; } = string.Empty;
            [JsonPropertyName("assignToEmail")]
            public string? AssignToEmail { get; set; }
            [JsonPropertyName("subject")]
            public string? Subject { get; set; }
        }

        [Authorize(Roles = "registrar")]
        [HttpPost("sections")]
        public async Task<IActionResult> CreateSection([FromBody] CreateSectionRequest request)
        {
            try
            {
                if (!int.TryParse(request.YearLevel, out var yearLevel) || yearLevel < 1 || yearLevel > 4 ||
                    !int.TryParse(request.SectionNum, out var sectionNumber) || sectionNumber < 1)
                    throw new ArgumentException("Year level must be from 1 to 4 and section number must be positive.");
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var transaction = await conn.BeginTransactionAsync();
                var program = await ResolveEnrollmentProgramAsync(conn, transaction, request.Department);
                request.Department = program.Name;

                using var cmd = new NpgsqlCommand("INSERT INTO AcademicSections (department, year_level, section_num) VALUES (@dept, @year, @sec) RETURNING id", conn, transaction);
                cmd.Parameters.AddWithValue("dept", request.Department);
                cmd.Parameters.AddWithValue("year", int.Parse(request.YearLevel));
                cmd.Parameters.AddWithValue("sec", int.Parse(request.SectionNum));
                
                var id = await cmd.ExecuteScalarAsync();

                if (!string.IsNullOrWhiteSpace(request.AssignToEmail))
                {
                    using var cmdUser = new NpgsqlCommand("SELECT id FROM Users WHERE LOWER(email) = LOWER(@email) LIMIT 1", conn, transaction);
                    cmdUser.Parameters.AddWithValue("email", request.AssignToEmail);
                    var userIdObj = await cmdUser.ExecuteScalarAsync();
                    
                    if (userIdObj != null && userIdObj != DBNull.Value)
                    {
                        using var cmdAssign = new NpgsqlCommand(@"
                            INSERT INTO FacultySections (user_id, department, section, year_level, subject) 
                            VALUES (@uid, @dept, @sec, @year, @subj) 
                            ON CONFLICT (user_id, department, section, subject) DO NOTHING", conn, transaction);
                        cmdAssign.Parameters.AddWithValue("uid", Convert.ToInt32(userIdObj));
                        cmdAssign.Parameters.AddWithValue("dept", request.Department);
                        cmdAssign.Parameters.AddWithValue("sec", request.SectionNum);
                        cmdAssign.Parameters.AddWithValue("year", request.YearLevel);
                        cmdAssign.Parameters.AddWithValue("subj", request.Subject != null ? (object)request.Subject.Trim() : DBNull.Value);
                        await cmdAssign.ExecuteNonQueryAsync();
                    }
                }

                await transaction.CommitAsync();

                await NotifyAcademicDataChangedAsync("section_created", request.Department, User.Identity?.Name);
                return Ok(new { status = "Success", message = "Section created successfully", id = id });
            }
            catch (PostgresException ex) when (ex.SqlState == "23505")
            {
                return BadRequest(new { status = "Error", message = "This section already exists in the department." });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [Authorize(Roles = "registrar,department_admin,faculty")]
        [HttpGet("sections/department/{department}")]
        public async Task<IActionResult> GetDepartmentSections(string department)
        {
            try
            {
                var sections = new List<object>();
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                using var cmd = new NpgsqlCommand(@"
                    SELECT s.id, s.department, s.year_level, s.section_num FROM academicsections s
                    WHERE LOWER(s.department) = LOWER(@dept) OR EXISTS (
                        SELECT 1 FROM academic_programs p
                        WHERE LOWER(@dept) IN (LOWER(p.program_code), LOWER(p.program_name))
                          AND LOWER(s.department) IN (LOWER(p.program_code), LOWER(p.program_name)))
                    ORDER BY s.year_level, s.section_num", conn);
                cmd.Parameters.AddWithValue("dept", department);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    sections.Add(new
                    {
                        id = reader.GetInt32(0).ToString(),
                        department = reader.GetString(1),
                        yearLevel = reader.GetInt32(2).ToString(),
                        sectionNum = reader.GetInt32(3).ToString()
                    });
                }

                return Ok(new { status = "Success", data = sections });
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("does not exist")) return Ok(new { status = "Success", data = new List<object>() });
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [Authorize(Roles = "registrar")]
        [HttpPost("sections/{id}/enroll")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> EnrollStudents(string id, [FromForm] IFormFile file)
        {
            if (file == null || file.Length == 0) return BadRequest(new { status = "Error", message = "A .csv or .xlsx file is required." });
            if (!int.TryParse(id, out var sectionId))
                return BadRequest(new { status = "Error", message = "Invalid section ID." });

            try
            {
                using var connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync();
                await using var command = new NpgsqlCommand(
                    "SELECT department, year_level, section_num FROM academicsections WHERE id = @id", connection);
                command.Parameters.AddWithValue("id", sectionId);
                await using var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                    return NotFound(new { status = "Error", message = "Section not found." });

                var department = reader.GetString(0);
                var yearLevel = reader.GetInt32(1).ToString();
                var section = $"{yearLevel}-{reader.GetInt32(2)}";

                // Reuse the official bulk-enrollment pipeline. Existing students
                // can be sectioned with ID-only rosters; unknown students must
                // still provide their real name and birthday.
                return await BulkUploadStudents(
                    file,
                    department,
                    "enroll",
                    null,
                    CurrentSchoolYear(),
                    CurrentSemester(),
                    yearLevel,
                    section);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [Authorize(Roles = "registrar")]
        [HttpDelete("sections/{id}")]
        public async Task<IActionResult> DeleteSection(string id)
        {
            if (!int.TryParse(id, out int sectionId)) return BadRequest(new { status = "Error", message = "Invalid section ID format." });

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                
                string dept = "", year = "", secNum = "";
                using (var getCmd = new NpgsqlCommand("SELECT department, year_level, section_num FROM AcademicSections WHERE id = @id", conn))
                {
                    getCmd.Parameters.AddWithValue("id", sectionId);
                    using var reader = await getCmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        dept = reader.GetString(0);
                        year = reader.GetInt32(1).ToString();
                        secNum = reader.GetInt32(2).ToString();
                    }
                    else return Ok(new { status = "Success", message = "Section already deleted." });
                }

                using var tx = await conn.BeginTransactionAsync();

                using var cmdFac = new NpgsqlCommand("DELETE FROM FacultySections WHERE department = @dept AND year_level = @year AND section = @sec", conn, tx);
                cmdFac.Parameters.AddWithValue("dept", dept);
                cmdFac.Parameters.AddWithValue("year", year);
                cmdFac.Parameters.AddWithValue("sec", secNum);
                await cmdFac.ExecuteNonQueryAsync();

                using var cmdSec = new NpgsqlCommand("DELETE FROM AcademicSections WHERE id = @id", conn, tx);
                cmdSec.Parameters.AddWithValue("id", sectionId);
                await cmdSec.ExecuteNonQueryAsync();

                await tx.CommitAsync();
                await NotifyAcademicDataChangedAsync("section_deleted", dept, User.Identity?.Name);
                return Ok(new { status = "Success", message = "Section deleted successfully." });
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        [Authorize(Roles = "registrar")]
        [HttpDelete("sections/department/{department}")]
        public async Task<IActionResult> DeleteAllDepartmentSections(string department)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var tx = await conn.BeginTransactionAsync();

                using var cmdFac = new NpgsqlCommand("DELETE FROM FacultySections WHERE department = @dept", conn, tx);
                cmdFac.Parameters.AddWithValue("dept", department);
                await cmdFac.ExecuteNonQueryAsync();

                using var cmdSec = new NpgsqlCommand("DELETE FROM AcademicSections WHERE department = @dept", conn, tx);
                cmdSec.Parameters.AddWithValue("dept", department);
                await cmdSec.ExecuteNonQueryAsync();

                await tx.CommitAsync();
                await NotifyAcademicDataChangedAsync("department_sections_deleted", department, User.Identity?.Name);
                return Ok(new { status = "Success", message = $"All academic sections for {department} have been removed." });
            }
            catch (Exception ex) { return StatusCode(500, new { status = "Error", message = ex.Message }); }
        }

        private static readonly HashSet<string> AllowedSharedClientStateKeys = new(StringComparer.OrdinalIgnoreCase)
        {
            "chairpersonStudentBatches",
            "chairpersonSubmissionLogs",
            "studentMasterlist",
            "studentSections",
            "registrarAssignments",
            "chairpersonSectionReviews",
            "studentPublishedGrades",
            "graduatingStudents",
            "irregularSubjectAssignments",
            "encodingPeriod",
            "facultyLoadResetAt",
            "STUDENT_BATCHES_KEY",
            "STUDENT_SUBMISSION_LOGS_KEY"
        };

        public class SharedClientStateRequest
        {
            public JsonElement Value { get; set; }
        }

        private static bool IsAllowedSharedClientStateKey(string key) =>
            !string.IsNullOrWhiteSpace(key) && AllowedSharedClientStateKeys.Contains(key);

        private static async Task EnsureSharedClientStateTableAsync(NpgsqlConnection conn)
        {
            if (System.Threading.Volatile.Read(ref _sharedStateSchemaInitialized)) return;

            await SharedStateSchemaLock.WaitAsync();
            try
            {
                if (System.Threading.Volatile.Read(ref _sharedStateSchemaInitialized)) return;
                using var cmd = new NpgsqlCommand(@"
                    CREATE TABLE IF NOT EXISTS shared_client_state (
                        key VARCHAR(120) PRIMARY KEY,
                        value JSONB NOT NULL,
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_by VARCHAR(255)
                    );", conn);
                await cmd.ExecuteNonQueryAsync();
                System.Threading.Volatile.Write(ref _sharedStateSchemaInitialized, true);
            }
            finally
            {
                SharedStateSchemaLock.Release();
            }
        }

        [Authorize]
        [HttpGet("shared-state/{key}")]
        public async Task<IActionResult> GetSharedClientState(string key)
        {
            if (!IsAllowedSharedClientStateKey(key))
                return BadRequest(new { status = "Error", message = "Shared state key is not allowed." });

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureSharedClientStateTableAsync(conn);

                using var cmd = new NpgsqlCommand("SELECT value::text, updated_at FROM shared_client_state WHERE key = @key", conn);
                cmd.Parameters.AddWithValue("key", key);
                using var reader = await cmd.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                    return Ok(new { status = "Success", key, value = (object?)null, updatedAt = (DateTime?)null });

                var rawValue = reader.GetString(0);
                var value = JsonSerializer.Deserialize<JsonElement>(rawValue);
                return Ok(new
                {
                    status = "Success",
                    key,
                    value,
                    updatedAt = reader.GetDateTime(1)
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }

        [Authorize(Roles = "department_admin,registrar")]
        [HttpPut("shared-state/{key}")]
        public async Task<IActionResult> SaveSharedClientState(string key, [FromBody] SharedClientStateRequest request)
        {
            if (!IsAllowedSharedClientStateKey(key))
                return BadRequest(new { status = "Error", message = "Shared state key is not allowed." });
            if (User.IsInRole("department_admin") &&
                !key.Equals("registrarAssignments", StringComparison.OrdinalIgnoreCase))
                return Forbid();

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureSharedClientStateTableAsync(conn);

                var valueJson = request.Value.GetRawText();
                using var cmd = new NpgsqlCommand(@"
                    INSERT INTO shared_client_state (key, value, updated_at, updated_by)
                    VALUES (@key, @value::jsonb, CURRENT_TIMESTAMP, @updatedBy)
                    ON CONFLICT (key)
                    DO UPDATE SET value = EXCLUDED.value,
                                  updated_at = EXCLUDED.updated_at,
                                  updated_by = EXCLUDED.updated_by;", conn);
                cmd.Parameters.AddWithValue("key", key);
                cmd.Parameters.AddWithValue("value", valueJson);
                cmd.Parameters.AddWithValue("updatedBy", (object?)User.Identity?.Name ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync();

                await NotifyAcademicDataChangedAsync("shared_client_state_updated", null, User.Identity?.Name);
                return Ok(new { status = "Success", key });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "Error", message = ex.Message });
            }
        }
    }
}
