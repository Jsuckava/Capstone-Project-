using BlockGo.Models;
using BlockGo.Services;
using Client_app.Models;
using Client_app.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using NpgsqlTypes;

namespace Client_app.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    public sealed class CurriculumsController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly IAuditLogService _auditLog;
        private readonly IBlockchainService _blockchain;
        private readonly ILogger<CurriculumsController> _logger;

        public CurriculumsController(
            IConfiguration configuration,
            IAuditLogService auditLog,
            IBlockchainService blockchain,
            ILogger<CurriculumsController> logger)
        {
            _connectionString = configuration.GetConnectionString("MasterConnection")
                ?? configuration.GetConnectionString("PostgresConnection")
                ?? throw new InvalidOperationException("A PostgreSQL write connection is required.");
            _auditLog = auditLog;
            _blockchain = blockchain;
            _logger = logger;
        }

        [HttpGet("programs")]
        public async Task<IActionResult> GetPrograms(CancellationToken cancellationToken)
        {
            var programs = new List<object>();
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(@"
                SELECT program_id, program_code, program_name
                FROM academic_programs WHERE is_active = TRUE ORDER BY program_name;", connection);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                programs.Add(new { programId = reader.GetInt32(0), programCode = reader.GetString(1), programName = reader.GetString(2) });
            }
            return Ok(new { status = "Success", data = programs });
        }

        [HttpGet]
        [Authorize(Roles = "department_admin,registrar")]
        public async Task<IActionResult> GetAll([FromQuery] string? status, CancellationToken cancellationToken)
        {
            var role = ActorRole();
            var actor = ActorEmail();
            await using var connection = await OpenConnectionAsync(cancellationToken);
            var ids = new List<long>();
            var sql = role == "registrar"
                ? @"SELECT c.curriculum_id FROM curriculums c WHERE (@status IS NULL OR c.status = @status) ORDER BY c.updated_at DESC"
                : @"SELECT c.curriculum_id
                    FROM curriculums c
                    JOIN academic_programs p ON p.program_id = c.program_id
                    JOIN users u ON LOWER(u.email) = LOWER(@actor)
                    JOIN adminprofiles ap ON ap.user_id = u.id
                    WHERE (LOWER(ap.department) = LOWER(p.program_name) OR LOWER(ap.department) = LOWER(p.program_code))
                      AND (@status IS NULL OR c.status = @status)
                    ORDER BY c.updated_at DESC";
            await using (var command = new NpgsqlCommand(sql, connection))
            {
                var statusParameter = command.Parameters.Add("status", NpgsqlTypes.NpgsqlDbType.Varchar);
                statusParameter.Value = (object?)NormalizeOptionalStatus(status) ?? DBNull.Value;
                if (role != "registrar") command.Parameters.AddWithValue("actor", actor);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken)) ids.Add(reader.GetInt64(0));
            }

            var curricula = new List<CurriculumDto>();
            foreach (var id in ids) curricula.Add(await LoadCurriculumAsync(connection, id, cancellationToken));
            return Ok(new { status = "Success", data = curricula });
        }

        [HttpGet("{id:long}")]
        [Authorize(Roles = "student,faculty,department_admin,registrar")]
        public async Task<IActionResult> GetById(long id, CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            var curriculum = await TryLoadCurriculumAsync(connection, id, cancellationToken);
            if (curriculum is null) return NotFound(new { status = "Error", message = "Curriculum not found." });
            if (!await CanViewAsync(connection, curriculum, cancellationToken)) return Forbid();
            return Ok(new { status = "Success", data = curriculum });
        }

        [HttpPost]
        [Authorize(Roles = "department_admin")]
        public async Task<IActionResult> Create([FromBody] CreateCurriculumRequest request, CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            var program = await ResolveOwnedProgramAsync(connection, transaction, actor.Id, request.ProgramCode, cancellationToken);

            long curriculumId;
            try
            {
                await using var command = new NpgsqlCommand(@"
                    INSERT INTO curriculums
                        (curriculum_code, curriculum_name, program_id, curriculum_version, school_year, status, created_by)
                    VALUES (@code, @name, @programId, @version, @schoolYear, 'DRAFT', @actorId)
                    RETURNING curriculum_id;", connection, transaction);
                command.Parameters.AddWithValue("code", RequiredTrim(request.CurriculumCode, "Curriculum code"));
                command.Parameters.AddWithValue("name", RequiredTrim(request.CurriculumName, "Curriculum name"));
                command.Parameters.AddWithValue("programId", program.Id);
                command.Parameters.AddWithValue("version", RequiredTrim(request.CurriculumVersion, "Curriculum version"));
                command.Parameters.AddWithValue("schoolYear", (object?)request.SchoolYear?.Trim() ?? DBNull.Value);
                command.Parameters.AddWithValue("actorId", actor.Id);
                curriculumId = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Conflict(new { status = "Error", message = "That curriculum code or program version already exists." });
            }

            await _auditLog.LogAsync(actor.Email, actor.Role, "CURRICULUM_CREATED", "curriculum", curriculumId.ToString(), null,
                new { request.CurriculumCode, request.CurriculumName, program.Code, request.CurriculumVersion, status = CurriculumStatuses.Draft },
                "Chairperson created a curriculum draft.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CreatedAtAction(nameof(GetById), new { id = curriculumId }, new { status = "Success", data = await LoadCurriculumAsync(connection, curriculumId, cancellationToken) });
        }

        [HttpPut("{id:long}")]
        [Authorize(Roles = "department_admin")]
        public async Task<IActionResult> Update(long id, [FromBody] UpdateCurriculumRequest request, CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            var editable = await RequireEditableOwnedCurriculumAsync(connection, transaction, id, cancellationToken);
            try
            {
                await using var command = new NpgsqlCommand(@"
                    UPDATE curriculums
                    SET curriculum_code = @code, curriculum_name = @name, curriculum_version = @version,
                        school_year = @schoolYear,
                        status = CASE WHEN status = 'RETURNED' THEN 'DRAFT' ELSE status END,
                        registrar_comment = CASE WHEN status = 'RETURNED' THEN registrar_comment ELSE registrar_comment END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE curriculum_id = @id;", connection, transaction);
                command.Parameters.AddWithValue("code", RequiredTrim(request.CurriculumCode, "Curriculum code"));
                command.Parameters.AddWithValue("name", RequiredTrim(request.CurriculumName, "Curriculum name"));
                command.Parameters.AddWithValue("version", RequiredTrim(request.CurriculumVersion, "Curriculum version"));
                command.Parameters.AddWithValue("schoolYear", (object?)request.SchoolYear?.Trim() ?? DBNull.Value);
                command.Parameters.AddWithValue("id", id);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Conflict(new { status = "Error", message = "That curriculum code or program version already exists." });
            }
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            await _auditLog.LogAsync(actor.Email, actor.Role, "CURRICULUM_UPDATED", "curriculum", id.ToString(), editable, request,
                "Chairperson updated curriculum draft metadata.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { status = "Success", data = await LoadCurriculumAsync(connection, id, cancellationToken) });
        }

        [HttpPost("{id:long}/subjects")]
        [Authorize(Roles = "department_admin")]
        public async Task<IActionResult> AddSubject(long id, [FromBody] CurriculumSubjectRequest request, CancellationToken cancellationToken)
        {
            NormalizeAndValidateSubject(request);
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await RequireEditableOwnedCurriculumAsync(connection, transaction, id, cancellationToken);
            await ValidatePrerequisiteAsync(connection, transaction, id, request.Prerequisite, null, cancellationToken);
            long subjectId;
            try
            {
                await using var command = new NpgsqlCommand(@"
                    INSERT INTO curriculum_subjects
                        (curriculum_id, subject_code, subject_title, units, lecture_hours, laboratory_hours,
                         prerequisite, year_level, semester, subject_type)
                    VALUES (@curriculumId, @code, @title, @units, @lecture, @laboratory,
                            @prerequisite, @yearLevel, @semester, @subjectType)
                    RETURNING subject_id;", connection, transaction);
                AddSubjectParameters(command, id, request);
                subjectId = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Conflict(new { status = "Error", message = "That subject code already exists in the selected year and semester." });
            }
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            await TouchCurriculumAsync(connection, transaction, id, cancellationToken);
            await _auditLog.LogAsync(actor.Email, actor.Role, "SUBJECT_ADDED", "curriculum", id.ToString(), null,
                new { subjectId, request.SubjectCode, request.YearLevel, request.Semester },
                "Chairperson added a curriculum subject.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { status = "Success", data = await LoadCurriculumAsync(connection, id, cancellationToken) });
        }

        [HttpPut("{id:long}/subjects/{subjectId:long}")]
        [Authorize(Roles = "department_admin")]
        public async Task<IActionResult> UpdateSubject(long id, long subjectId, [FromBody] CurriculumSubjectRequest request, CancellationToken cancellationToken)
        {
            NormalizeAndValidateSubject(request);
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await RequireEditableOwnedCurriculumAsync(connection, transaction, id, cancellationToken);
            await ValidatePrerequisiteAsync(connection, transaction, id, request.Prerequisite, subjectId, cancellationToken);
            try
            {
                await using var command = new NpgsqlCommand(@"
                    UPDATE curriculum_subjects
                    SET subject_code = @code, subject_title = @title, units = @units,
                        lecture_hours = @lecture, laboratory_hours = @laboratory,
                        prerequisite = @prerequisite, year_level = @yearLevel,
                        semester = @semester, subject_type = @subjectType, updated_at = CURRENT_TIMESTAMP
                    WHERE subject_id = @subjectId AND curriculum_id = @curriculumId;", connection, transaction);
                AddSubjectParameters(command, id, request);
                command.Parameters.AddWithValue("subjectId", subjectId);
                if (await command.ExecuteNonQueryAsync(cancellationToken) == 0) return NotFound(new { status = "Error", message = "Subject not found." });
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Conflict(new { status = "Error", message = "That subject code already exists in the selected year and semester." });
            }
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            await TouchCurriculumAsync(connection, transaction, id, cancellationToken);
            await _auditLog.LogAsync(actor.Email, actor.Role, "SUBJECT_UPDATED", "curriculum", id.ToString(), null,
                new { subjectId, request.SubjectCode, request.YearLevel, request.Semester },
                "Chairperson updated a curriculum subject.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { status = "Success", data = await LoadCurriculumAsync(connection, id, cancellationToken) });
        }

        [HttpDelete("{id:long}/subjects/{subjectId:long}")]
        [Authorize(Roles = "department_admin")]
        public async Task<IActionResult> RemoveSubject(long id, long subjectId, CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await RequireEditableOwnedCurriculumAsync(connection, transaction, id, cancellationToken);
            await using var command = new NpgsqlCommand(
                "DELETE FROM curriculum_subjects WHERE subject_id = @subjectId AND curriculum_id = @curriculumId RETURNING subject_code;", connection, transaction);
            command.Parameters.AddWithValue("subjectId", subjectId);
            command.Parameters.AddWithValue("curriculumId", id);
            var subjectCode = (await command.ExecuteScalarAsync(cancellationToken))?.ToString();
            if (subjectCode is null) return NotFound(new { status = "Error", message = "Subject not found." });
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            await TouchCurriculumAsync(connection, transaction, id, cancellationToken);
            await _auditLog.LogAsync(actor.Email, actor.Role, "SUBJECT_REMOVED", "curriculum", id.ToString(),
                new { subjectId, subjectCode }, null, "Chairperson removed a curriculum subject.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { status = "Success", data = await LoadCurriculumAsync(connection, id, cancellationToken) });
        }

        [HttpPost("{id:long}/submit")]
        [Authorize(Roles = "department_admin")]
        public Task<IActionResult> Submit(long id, CancellationToken cancellationToken) =>
            TransitionAsync(id, new[] { CurriculumStatuses.Draft }, CurriculumStatuses.PendingApproval,
                "CURRICULUM_SUBMITTED", "Chairperson submitted the curriculum for Registrar approval.", null, false, cancellationToken);

        [HttpPost("{id:long}/approve")]
        [Authorize(Roles = "registrar")]
        public Task<IActionResult> Approve(long id, CancellationToken cancellationToken) =>
            TransitionAsync(id, new[] { CurriculumStatuses.PendingApproval }, CurriculumStatuses.Approved,
                "CURRICULUM_APPROVED", "Registrar approved the curriculum.", null, true, cancellationToken);

        [HttpPost("{id:long}/return")]
        [Authorize(Roles = "registrar")]
        public Task<IActionResult> Return(long id, [FromBody] ReturnCurriculumRequest request, CancellationToken cancellationToken) =>
            TransitionAsync(id, new[] { CurriculumStatuses.PendingApproval }, CurriculumStatuses.Returned,
                "CURRICULUM_RETURNED", "Registrar returned the curriculum for revision.", RequiredTrim(request.Reason, "Return reason"), false, cancellationToken);

        [HttpPost("{id:long}/publish")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> Publish(long id, CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            var curriculum = await RequireStatusAsync(connection, transaction, id, new[] { CurriculumStatuses.Approved }, cancellationToken);
            await ValidateCompleteCurriculumAsync(connection, transaction, id, cancellationToken);
            var actor = await GetActorAsync(connection, transaction, cancellationToken);

            var archivedIds = new List<long>();
            await using (var archive = new NpgsqlCommand(@"
                UPDATE curriculums SET status = 'ARCHIVED', updated_at = CURRENT_TIMESTAMP
                WHERE program_id = @programId AND status = 'PUBLISHED' AND curriculum_id <> @id
                RETURNING curriculum_id;", connection, transaction))
            {
                archive.Parameters.AddWithValue("programId", curriculum.ProgramId);
                archive.Parameters.AddWithValue("id", id);
                await using var reader = await archive.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken)) archivedIds.Add(reader.GetInt64(0));
            }
            foreach (var archivedId in archivedIds)
            {
                await _auditLog.LogAsync(actor.Email, actor.Role, "CURRICULUM_ARCHIVED", "curriculum", archivedId.ToString(),
                    new { status = CurriculumStatuses.Published }, new { status = CurriculumStatuses.Archived },
                    "Previous published curriculum was archived when a new version was published.", IpAddress(), connection, transaction, cancellationToken);
            }

            await using (var publish = new NpgsqlCommand(@"
                UPDATE curriculums SET status = 'PUBLISHED', published_at = CURRENT_TIMESTAMP,
                    reviewed_by = @actorId, reviewed_at = COALESCE(reviewed_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP
                WHERE curriculum_id = @id;", connection, transaction))
            {
                publish.Parameters.AddWithValue("actorId", actor.Id);
                publish.Parameters.AddWithValue("id", id);
                await publish.ExecuteNonQueryAsync(cancellationToken);
            }
            await _auditLog.LogAsync(actor.Email, actor.Role, "CURRICULUM_PUBLISHED", "curriculum", id.ToString(),
                new { status = CurriculumStatuses.Approved }, new { status = CurriculumStatuses.Published },
                "Registrar published the approved curriculum.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            await TryRecordLedgerAuditAsync("CURRICULUM_PUBLISHED", id, actor, new[] { "status", "published_at" }, cancellationToken);
            foreach (var archivedId in archivedIds)
            {
                await TryRecordLedgerAuditAsync("CURRICULUM_ARCHIVED", archivedId, actor, new[] { "status" }, cancellationToken);
            }
            return Ok(new { status = "Success", data = await LoadCurriculumAsync(connection, id, cancellationToken) });
        }

        [HttpPost("{id:long}/archive")]
        [Authorize(Roles = "registrar")]
        public Task<IActionResult> Archive(long id, CancellationToken cancellationToken) =>
            TransitionAsync(id, new[] { CurriculumStatuses.Published }, CurriculumStatuses.Archived,
                "CURRICULUM_ARCHIVED", "Registrar archived the published curriculum.", null, true, cancellationToken);

        [HttpPut("{id:long}/students")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> AssignStudent(long id, [FromBody] AssignStudentCurriculumRequest request, CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            var curriculum = await RequireStatusAsync(connection, transaction, id, new[] { CurriculumStatuses.Published }, cancellationToken);
            await using var command = new NpgsqlCommand(@"
                UPDATE studentprofiles sp
                SET curriculum_id = @curriculumId
                FROM users u, academic_programs p
                WHERE sp.user_id = u.id AND p.program_id = @programId
                  AND LOWER(u.email) = LOWER(@studentEmail) AND LOWER(u.role) = 'student'
                  AND (LOWER(sp.department) = LOWER(p.program_name) OR LOWER(sp.department) = LOWER(p.program_code));", connection, transaction);
            command.Parameters.AddWithValue("curriculumId", id);
            command.Parameters.AddWithValue("programId", curriculum.ProgramId);
            command.Parameters.AddWithValue("studentEmail", request.StudentEmail.Trim());
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            {
                return BadRequest(new { status = "Error", message = "Student not found or the curriculum program does not match the student program." });
            }

            var enrollmentUpdated = false;
            await using (var enrollment = new NpgsqlCommand(@"
                UPDATE student_enrollments se
                SET curriculum_id = @curriculumId,
                    updated_at = CURRENT_TIMESTAMP
                WHERE se.enrollment_id = (
                    SELECT latest.enrollment_id
                    FROM student_enrollments latest
                    JOIN users student ON student.id = latest.student_user_id
                    WHERE LOWER(student.email) = LOWER(@studentEmail)
                      AND latest.program_id = @programId
                    ORDER BY latest.updated_at DESC, latest.enrollment_id DESC
                    LIMIT 1
                );", connection, transaction))
            {
                enrollment.Parameters.AddWithValue("curriculumId", id);
                enrollment.Parameters.AddWithValue("programId", curriculum.ProgramId);
                enrollment.Parameters.AddWithValue("studentEmail", request.StudentEmail.Trim());
                enrollmentUpdated = await enrollment.ExecuteNonQueryAsync(cancellationToken) > 0;
            }
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            await _auditLog.LogAsync(actor.Email, actor.Role, "STUDENT_CURRICULUM_ASSIGNED", "curriculum", id.ToString(), null,
                new { student = request.StudentEmail.Trim().ToLowerInvariant(), enrollmentUpdated },
                "Registrar assigned a curriculum version to a student profile and its latest enrollment.", IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { status = "Success", message = "Curriculum assigned to student." });
        }

        [HttpGet("student")]
        [Authorize(Roles = "student")]
        public async Task<IActionResult> GetStudentCurriculum(CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(@"
                SELECT COALESCE(enrollment.curriculum_id, sp.curriculum_id), COALESCE(
                    enrollment.curriculum_id,
                    sp.curriculum_id,
                    (SELECT c.curriculum_id
                     FROM curriculums c
                     JOIN academic_programs p ON p.program_id = c.program_id
                     WHERE c.status = 'PUBLISHED'
                       AND (
                           p.program_id = enrollment.program_id
                           OR (enrollment.program_id IS NULL AND
                               (LOWER(p.program_name) = LOWER(sp.department) OR LOWER(p.program_code) = LOWER(sp.department)))
                       )
                     ORDER BY c.published_at DESC NULLS LAST, c.curriculum_id DESC LIMIT 1)
                )
                FROM users u
                JOIN studentprofiles sp ON sp.user_id = u.id
                LEFT JOIN LATERAL (
                    SELECT se.curriculum_id, se.program_id
                    FROM student_enrollments se
                    WHERE se.student_user_id = u.id
                    ORDER BY se.updated_at DESC, se.enrollment_id DESC
                    LIMIT 1
                ) enrollment ON TRUE
                WHERE LOWER(u.email) = LOWER(@actor) AND LOWER(u.role) = 'student';", connection);
            command.Parameters.AddWithValue("actor", ActorEmail());
            long? assignedId = null;
            long? resolvedId = null;
            await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                if (await reader.ReadAsync(cancellationToken))
                {
                    assignedId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
                    resolvedId = reader.IsDBNull(1) ? null : reader.GetInt64(1);
                }
            }
            if (!resolvedId.HasValue) return NotFound(new { status = "Error", message = "No published curriculum is assigned to your program." });
            var curriculum = await LoadCurriculumAsync(connection, resolvedId.Value, cancellationToken);
            var canViewArchivedAssignment = assignedId == resolvedId && curriculum.Status == CurriculumStatuses.Archived;
            if (curriculum.Status != CurriculumStatuses.Published && !canViewArchivedAssignment)
                return NotFound(new { status = "Error", message = "Your assigned curriculum is not available." });
            return Ok(new { status = "Success", data = curriculum });
        }

        [HttpGet("faculty")]
        [Authorize(Roles = "faculty")]
        public async Task<IActionResult> GetFacultyCurricula(CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            var ids = new List<long>();
            await using (var command = new NpgsqlCommand(@"
                SELECT DISTINCT c.curriculum_id
                FROM users u
                LEFT JOIN facultyprofiles fp ON fp.user_id = u.id
                LEFT JOIN facultysections fs ON fs.user_id = u.id
                JOIN academic_programs p ON LOWER(p.program_name) = LOWER(COALESCE(fs.department, fp.department))
                                         OR LOWER(p.program_code) = LOWER(COALESCE(fs.department, fp.department))
                JOIN curriculums c ON c.program_id = p.program_id AND c.status = 'PUBLISHED'
                WHERE LOWER(u.email) = LOWER(@actor) AND LOWER(u.role) = 'faculty'
                ORDER BY c.curriculum_id DESC;", connection))
            {
                command.Parameters.AddWithValue("actor", ActorEmail());
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken)) ids.Add(reader.GetInt64(0));
            }
            var curricula = new List<CurriculumDto>();
            foreach (var id in ids) curricula.Add(await LoadCurriculumAsync(connection, id, cancellationToken));
            return Ok(new { status = "Success", data = curricula });
        }

        private async Task<IActionResult> TransitionAsync(
            long id,
            IReadOnlyCollection<string> fromStatuses,
            string toStatus,
            string action,
            string description,
            string? registrarComment,
            bool writeLedger,
            CancellationToken cancellationToken)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            var role = ActorRole();
            var curriculum = role == "department_admin"
                ? await RequireEditableOwnedCurriculumAsync(connection, transaction, id, cancellationToken, fromStatuses)
                : await RequireStatusAsync(connection, transaction, id, fromStatuses, cancellationToken);
            if (toStatus == CurriculumStatuses.PendingApproval) await ValidateCompleteCurriculumAsync(connection, transaction, id, cancellationToken);
            var actor = await GetActorAsync(connection, transaction, cancellationToken);

            await using var command = new NpgsqlCommand(@"
                UPDATE curriculums SET status = @status, registrar_comment = COALESCE(@comment, registrar_comment),
                    submitted_at = CASE WHEN @status = 'PENDING_APPROVAL' THEN CURRENT_TIMESTAMP ELSE submitted_at END,
                    reviewed_by = CASE WHEN @status IN ('RETURNED', 'APPROVED') THEN @actorId ELSE reviewed_by END,
                    reviewed_at = CASE WHEN @status IN ('RETURNED', 'APPROVED') THEN CURRENT_TIMESTAMP ELSE reviewed_at END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE curriculum_id = @id;", connection, transaction);
            command.Parameters.AddWithValue("status", toStatus);
            command.Parameters.AddWithValue("comment", (object?)registrarComment ?? DBNull.Value);
            command.Parameters.AddWithValue("actorId", actor.Id);
            command.Parameters.AddWithValue("id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
            await _auditLog.LogAsync(actor.Email, actor.Role, action, "curriculum", id.ToString(),
                new { status = curriculum.Status }, new { status = toStatus, registrarComment }, description,
                IpAddress(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            if (writeLedger) await TryRecordLedgerAuditAsync(action, id, actor, new[] { "status" }, cancellationToken);
            return Ok(new { status = "Success", data = await LoadCurriculumAsync(connection, id, cancellationToken) });
        }

        private async Task TryRecordLedgerAuditAsync(string eventType, long curriculumId, Actor actor, IReadOnlyCollection<string> fields, CancellationToken cancellationToken)
        {
            try
            {
                await _blockchain.RecordAuditEventAsync(new BlockchainAuditEvent
                {
                    EventType = eventType,
                    EntityId = curriculumId.ToString(),
                    ActorId = actor.Email,
                    ActorRole = actor.Role,
                    ChangedFields = fields,
                    Description = $"{eventType} for curriculum {curriculumId}."
                }, actor.Email);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Curriculum event {EventType} for {CurriculumId} was not recorded on Fabric.", eventType, curriculumId);
            }
        }

        private async Task<bool> CanViewAsync(NpgsqlConnection connection, CurriculumDto curriculum, CancellationToken cancellationToken)
        {
            var role = ActorRole();
            if (role == "registrar") return true;
            if (role == "student")
            {
                if (curriculum.Status is not (CurriculumStatuses.Published or CurriculumStatuses.Archived)) return false;
                await using var command = new NpgsqlCommand(@"
                    SELECT COUNT(*)
                    FROM users u
                    JOIN studentprofiles sp ON sp.user_id = u.id
                    JOIN academic_programs p ON p.program_id = @programId
                    WHERE LOWER(u.email) = LOWER(@actor)
                      AND (
                          sp.curriculum_id = @curriculumId
                          OR EXISTS (
                              SELECT 1
                              FROM student_enrollments se
                              WHERE se.student_user_id = u.id
                                AND se.curriculum_id = @curriculumId
                          )
                          OR (@isPublished
                              AND sp.curriculum_id IS NULL
                              AND NOT EXISTS (
                                  SELECT 1 FROM student_enrollments assigned
                                  WHERE assigned.student_user_id = u.id
                                    AND assigned.curriculum_id IS NOT NULL
                              )
                              AND (LOWER(sp.department) = LOWER(p.program_name) OR LOWER(sp.department) = LOWER(p.program_code)))
                      );", connection);
                command.Parameters.AddWithValue("actor", ActorEmail());
                command.Parameters.AddWithValue("programId", curriculum.ProgramId);
                command.Parameters.AddWithValue("curriculumId", curriculum.CurriculumId);
                command.Parameters.AddWithValue("isPublished", curriculum.Status == CurriculumStatuses.Published);
                return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0;
            }
            if (role == "faculty")
            {
                if (curriculum.Status != CurriculumStatuses.Published) return false;
                await using var facultyCommand = new NpgsqlCommand(@"
                    SELECT COUNT(*)
                    FROM users u
                    JOIN academic_programs p ON p.program_id = @programId
                    WHERE LOWER(u.email) = LOWER(@actor)
                      AND (
                          EXISTS (SELECT 1 FROM facultyprofiles fp WHERE fp.user_id = u.id
                                  AND (LOWER(fp.department) = LOWER(p.program_name) OR LOWER(fp.department) = LOWER(p.program_code)))
                          OR EXISTS (SELECT 1 FROM facultysections fs WHERE fs.user_id = u.id
                                     AND (LOWER(fs.department) = LOWER(p.program_name) OR LOWER(fs.department) = LOWER(p.program_code)))
                      );", connection);
                facultyCommand.Parameters.AddWithValue("actor", ActorEmail());
                facultyCommand.Parameters.AddWithValue("programId", curriculum.ProgramId);
                return Convert.ToInt64(await facultyCommand.ExecuteScalarAsync(cancellationToken)) > 0;
            }
            await using (var command = new NpgsqlCommand($@"
                SELECT COUNT(*) FROM users u JOIN adminprofiles profile ON profile.user_id = u.id
                JOIN academic_programs p ON p.program_id = @programId
                WHERE LOWER(u.email) = LOWER(@actor)
                  AND (LOWER(profile.department) = LOWER(p.program_name) OR LOWER(profile.department) = LOWER(p.program_code));", connection))
            {
                command.Parameters.AddWithValue("actor", ActorEmail());
                command.Parameters.AddWithValue("programId", curriculum.ProgramId);
                return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0;
            }
        }

        private async Task<CurriculumDto> RequireEditableOwnedCurriculumAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            long id,
            CancellationToken cancellationToken,
            IReadOnlyCollection<string>? allowedStatuses = null)
        {
            allowedStatuses ??= new[] { CurriculumStatuses.Draft, CurriculumStatuses.Returned };
            var curriculum = await RequireStatusAsync(connection, transaction, id, allowedStatuses, cancellationToken);
            var actor = await GetActorAsync(connection, transaction, cancellationToken);
            await ResolveOwnedProgramAsync(connection, transaction, actor.Id, curriculum.ProgramCode, cancellationToken);
            return curriculum;
        }

        private static async Task<CurriculumDto> RequireStatusAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            long id,
            IReadOnlyCollection<string> allowedStatuses,
            CancellationToken cancellationToken)
        {
            var curriculum = await TryLoadCurriculumAsync(connection, id, cancellationToken, transaction)
                ?? throw new KeyNotFoundException("Curriculum not found.");
            if (!allowedStatuses.Contains(curriculum.Status))
            {
                throw new InvalidOperationException($"Curriculum status {curriculum.Status} cannot perform this transition.");
            }
            return curriculum;
        }

        private static async Task ValidateCompleteCurriculumAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, long id, CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT COUNT(*), COUNT(DISTINCT year_level),
                       COUNT(*) FILTER (WHERE subject_code IS NULL OR BTRIM(subject_code) = '' OR subject_title IS NULL OR BTRIM(subject_title) = '' OR units <= 0)
                FROM curriculum_subjects WHERE curriculum_id = @id;", connection, transaction);
            command.Parameters.AddWithValue("id", id);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);
            var count = reader.GetInt64(0);
            var years = reader.GetInt64(1);
            var invalid = reader.GetInt64(2);
            if (count == 0 || years < 4 || invalid > 0)
            {
                throw new InvalidOperationException("A curriculum must contain valid subjects for all four year levels before submission or publication.");
            }
        }

        private static void NormalizeAndValidateSubject(CurriculumSubjectRequest request)
        {
            request.SubjectCode = RequiredTrim(request.SubjectCode, "Subject code").ToUpperInvariant();
            request.SubjectTitle = RequiredTrim(request.SubjectTitle, "Subject title");
            request.Semester = RequiredTrim(request.Semester, "Semester").ToUpperInvariant();
            request.Prerequisite = string.IsNullOrWhiteSpace(request.Prerequisite) ? null : request.Prerequisite.Trim().ToUpperInvariant();
            request.SubjectType = string.IsNullOrWhiteSpace(request.SubjectType) ? null : request.SubjectType.Trim();
            if (request.YearLevel is < 1 or > 4) throw new ArgumentException("Year level must be between 1 and 4.");
            if (!CurriculumSemesters.All.Contains(request.Semester)) throw new ArgumentException("Semester must be FIRST, SECOND, or MIDYEAR.");
            if (request.Units <= 0 || request.Units > 20) throw new ArgumentException("Units must be greater than 0 and no more than 20.");
            if (request.LectureHours < 0 || request.LaboratoryHours < 0) throw new ArgumentException("Lecture and laboratory hours cannot be negative.");
            if (string.Equals(request.Prerequisite, request.SubjectCode, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("A subject cannot be its own prerequisite.");
        }

        private static async Task ValidatePrerequisiteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, long curriculumId, string? prerequisite, long? subjectId, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(prerequisite)) return;
            await using var command = new NpgsqlCommand(@"
                SELECT COUNT(*) FROM curriculum_subjects
                WHERE curriculum_id = @curriculumId AND LOWER(subject_code) = LOWER(@prerequisite)
                  AND (@subjectId IS NULL OR subject_id <> @subjectId);", connection, transaction);
            command.Parameters.AddWithValue("curriculumId", curriculumId);
            command.Parameters.AddWithValue("prerequisite", prerequisite);
            command.Parameters.AddWithValue("subjectId", (object?)subjectId ?? DBNull.Value);
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) == 0)
            {
                throw new ArgumentException("Prerequisite subject must already exist in this curriculum.");
            }
        }

        private static void AddSubjectParameters(NpgsqlCommand command, long curriculumId, CurriculumSubjectRequest request)
        {
            command.Parameters.AddWithValue("curriculumId", curriculumId);
            command.Parameters.AddWithValue("code", request.SubjectCode);
            command.Parameters.AddWithValue("title", request.SubjectTitle);
            command.Parameters.AddWithValue("units", request.Units);
            command.Parameters.AddWithValue("lecture", request.LectureHours);
            command.Parameters.AddWithValue("laboratory", request.LaboratoryHours);
            command.Parameters.AddWithValue("prerequisite", (object?)request.Prerequisite ?? DBNull.Value);
            command.Parameters.AddWithValue("yearLevel", request.YearLevel);
            command.Parameters.AddWithValue("semester", request.Semester);
            command.Parameters.AddWithValue("subjectType", (object?)request.SubjectType ?? DBNull.Value);
        }

        private static async Task TouchCurriculumAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, long id, CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                UPDATE curriculums SET status = CASE WHEN status = 'RETURNED' THEN 'DRAFT' ELSE status END,
                    updated_at = CURRENT_TIMESTAMP WHERE curriculum_id = @id;", connection, transaction);
            command.Parameters.AddWithValue("id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private async Task<(int Id, string Code, string Name)> ResolveOwnedProgramAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, int actorId, string programCode, CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT p.program_id, p.program_code, p.program_name
                FROM academic_programs p
                JOIN adminprofiles ap ON ap.user_id = @actorId
                JOIN users u ON u.id = ap.user_id
                WHERE LOWER(p.program_code) = LOWER(@programCode) AND p.is_active = TRUE
                  AND LOWER(u.role) = 'department_admin' AND u.is_active = TRUE
                  AND (LOWER(ap.department) = LOWER(p.program_name) OR LOWER(ap.department) = LOWER(p.program_code));", connection, transaction);
            command.Parameters.AddWithValue("actorId", actorId);
            command.Parameters.AddWithValue("programCode", programCode.Trim());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) throw new UnauthorizedAccessException("Chairpersons may manage only their assigned academic program.");
            return (reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
        }

        private async Task<Actor> GetActorAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT id, email, role FROM users
                WHERE LOWER(email) = LOWER(@email) AND is_active = TRUE AND LOWER(status) = 'approved';", connection, transaction);
            command.Parameters.AddWithValue("email", ActorEmail());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) throw new UnauthorizedAccessException("Authenticated account is not active.");
            return new Actor(reader.GetInt32(0), reader.GetString(1), NormalizeRole(reader.GetString(2)));
        }

        private static async Task<CurriculumDto?> TryLoadCurriculumAsync(NpgsqlConnection connection, long id, CancellationToken cancellationToken, NpgsqlTransaction? transaction = null)
        {
            CurriculumDto? curriculum = null;
            await using (var command = new NpgsqlCommand(@"
                SELECT c.curriculum_id, c.curriculum_code, c.curriculum_name, p.program_id, p.program_code,
                       p.program_name, c.curriculum_version, c.school_year, c.status, creator.email,
                       COALESCE(ap.full_name, creator.email), c.created_at, c.updated_at, c.submitted_at,
                       reviewer.email, c.reviewed_at, c.published_at, c.registrar_comment
                FROM curriculums c
                JOIN academic_programs p ON p.program_id = c.program_id
                JOIN users creator ON creator.id = c.created_by
                LEFT JOIN adminprofiles ap ON ap.user_id = creator.id
                LEFT JOIN users reviewer ON reviewer.id = c.reviewed_by
                WHERE c.curriculum_id = @id;", connection, transaction))
            {
                command.Parameters.AddWithValue("id", id);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken)) return null;
                curriculum = new CurriculumDto
                {
                    CurriculumId = reader.GetInt64(0), CurriculumCode = reader.GetString(1), CurriculumName = reader.GetString(2),
                    ProgramId = reader.GetInt32(3), ProgramCode = reader.GetString(4), ProgramName = reader.GetString(5),
                    CurriculumVersion = reader.GetString(6), SchoolYear = reader.IsDBNull(7) ? null : reader.GetString(7),
                    Status = reader.GetString(8), CreatedBy = reader.GetString(9), CreatedByName = reader.GetString(10),
                    CreatedAt = reader.GetFieldValue<DateTimeOffset>(11), UpdatedAt = reader.GetFieldValue<DateTimeOffset>(12),
                    SubmittedAt = reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13),
                    ReviewedBy = reader.IsDBNull(14) ? null : reader.GetString(14),
                    ReviewedAt = reader.IsDBNull(15) ? null : reader.GetFieldValue<DateTimeOffset>(15),
                    PublishedAt = reader.IsDBNull(16) ? null : reader.GetFieldValue<DateTimeOffset>(16),
                    RegistrarComment = reader.IsDBNull(17) ? null : reader.GetString(17)
                };
            }

            var subjects = new List<CurriculumSubjectDto>();
            await using (var command = new NpgsqlCommand(@"
                SELECT subject_id, subject_code, subject_title, units, lecture_hours, laboratory_hours,
                       prerequisite, year_level, semester, subject_type
                FROM curriculum_subjects WHERE curriculum_id = @id
                ORDER BY year_level, CASE semester WHEN 'FIRST' THEN 1 WHEN 'SECOND' THEN 2 ELSE 3 END, subject_code;", connection, transaction))
            {
                command.Parameters.AddWithValue("id", id);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    subjects.Add(new CurriculumSubjectDto
                    {
                        SubjectId = reader.GetInt64(0), SubjectCode = reader.GetString(1), SubjectTitle = reader.GetString(2),
                        Units = reader.GetDecimal(3), LectureHours = reader.GetDecimal(4), LaboratoryHours = reader.GetDecimal(5),
                        Prerequisite = reader.IsDBNull(6) ? null : reader.GetString(6), YearLevel = reader.GetInt16(7),
                        Semester = reader.GetString(8), SubjectType = reader.IsDBNull(9) ? null : reader.GetString(9)
                    });
                }
            }
            curriculum.Subjects = subjects;
            return curriculum;
        }

        private static async Task<CurriculumDto> LoadCurriculumAsync(NpgsqlConnection connection, long id, CancellationToken cancellationToken) =>
            await TryLoadCurriculumAsync(connection, id, cancellationToken) ?? throw new KeyNotFoundException("Curriculum not found.");

        private async Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
        {
            var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            return connection;
        }

        private string ActorEmail() => User.Identity?.Name ?? throw new UnauthorizedAccessException("Authenticated identity is missing.");
        private string ActorRole() => NormalizeRole(User.FindFirst("dbRole")?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value);
        private string? IpAddress() => HttpContext.Connection.RemoteIpAddress?.ToString();
        private static string NormalizeRole(string? role) => (role ?? string.Empty).Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_') switch
        {
            "dept_admin" or "deptadmin" or "chairperson" or "department_head" => "department_admin",
            var value => value
        };
        private static string? NormalizeOptionalStatus(string? status) => string.IsNullOrWhiteSpace(status) ? null : status.Trim().ToUpperInvariant();
        private static string RequiredTrim(string? value, string field) => string.IsNullOrWhiteSpace(value) ? throw new ArgumentException($"{field} is required.") : value.Trim();
        private sealed record Actor(int Id, string Email, string Role);
    }
}
