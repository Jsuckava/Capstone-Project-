using Npgsql;
using NpgsqlTypes;

namespace Client_app.Services;

// Enrollment is period-specific. StudentProfiles is only a current-profile snapshot.
public static class EnrollmentSectioningService
{
    public sealed record EnrolledStudent(long EnrollmentId, int Id, string StudentNo,
        string FullName, string Email, string? StudentEmail, string Department,
        string YearLevel, string EnrollmentStatus, int? AcademicSectionId, string? Section,
        string? Sex, long? CurriculumId, int? BatchYear, string SchoolYear, string Semester);

    public static async Task<List<EnrolledStudent>> GetUnassignedAsync(NpgsqlConnection connection,
        string? department, short? yearLevel, string? schoolYear, string? semester, string? departmentScope)
    {
        await using var command = new NpgsqlCommand(@"
            SELECT e.enrollment_id, u.id, e.student_no, COALESCE(sp.full_name, ''), u.email,
                   sp.student_email, p.program_name, e.year_level::text, e.status,
                   e.academic_section_id, e.section, sp.sex, e.curriculum_id, e.batch_year,
                   e.school_year, e.semester
            FROM student_enrollments e
            JOIN users u ON u.id = e.student_user_id
            JOIN studentprofiles sp ON sp.user_id = u.id
            JOIN academic_programs p ON p.program_id = e.program_id
            WHERE e.status = 'ENROLLED' AND e.academic_section_id IS NULL
              AND LOWER(u.role) = 'student' AND LOWER(u.status) = 'approved' AND u.is_active
              AND (@department IS NULL OR LOWER(p.program_code) = LOWER(@department)
                   OR LOWER(p.program_name) = LOWER(@department))
              AND (@scope IS NULL OR LOWER(p.program_code) = LOWER(@scope)
                   OR LOWER(p.program_name) = LOWER(@scope))
              AND (@yearLevel IS NULL OR e.year_level = @yearLevel)
              AND (@schoolYear IS NULL OR e.school_year = @schoolYear)
              AND (@semester IS NULL OR e.semester = @semester)
            ORDER BY e.student_no, e.school_year, e.semester;", connection);
        command.Parameters.Add("department", NpgsqlDbType.Text).Value = (object?)department ?? DBNull.Value;
        command.Parameters.Add("scope", NpgsqlDbType.Text).Value = (object?)departmentScope ?? DBNull.Value;
        command.Parameters.Add("yearLevel", NpgsqlDbType.Smallint).Value = (object?)yearLevel ?? DBNull.Value;
        command.Parameters.Add("schoolYear", NpgsqlDbType.Text).Value = (object?)schoolYear ?? DBNull.Value;
        command.Parameters.Add("semester", NpgsqlDbType.Text).Value = (object?)semester ?? DBNull.Value;
        var result = new List<EnrolledStudent>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            result.Add(new(reader.GetInt64(0), reader.GetInt32(1), reader.GetString(2),
                reader.GetString(3), reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.GetString(6), reader.GetString(7), reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetInt32(9), reader.IsDBNull(10) ? null : reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetInt64(12),
                reader.IsDBNull(13) ? null : reader.GetInt32(13), reader.GetString(14), reader.GetString(15)));
        return result;
    }

    public static async Task<(int Count, string Department)> AssignAsync(NpgsqlConnection connection,
        int sectionId, IEnumerable<string> studentIds, string schoolYear, string semester, string? departmentScope)
    {
        var identifiers = studentIds.Select(value => value?.Trim() ?? "").ToArray();
        if (identifiers.Length == 0 || identifiers.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("At least one nonblank student ID is required.");
        await using var transaction = await connection.BeginTransactionAsync();
        string department;
        int programId, yearLevel, sectionNumber;
        await using (var section = new NpgsqlCommand(@"
            SELECT s.department, s.year_level, s.section_num, p.program_id
            FROM academicsections s
            JOIN academic_programs p ON LOWER(s.department) IN (LOWER(p.program_code), LOWER(p.program_name))
            WHERE s.id = @id
              AND (@scope IS NULL OR LOWER(@scope) IN (LOWER(p.program_code), LOWER(p.program_name)))
            FOR SHARE OF s;", connection, transaction))
        {
            section.Parameters.AddWithValue("id", sectionId);
            section.Parameters.Add("scope", NpgsqlDbType.Text).Value = (object?)departmentScope ?? DBNull.Value;
            await using var reader = await section.ExecuteReaderAsync();
            if (!await reader.ReadAsync()) throw new KeyNotFoundException("Section not found in your academic program scope.");
            department = reader.GetString(0);
            yearLevel = reader.GetInt32(1);
            sectionNumber = reader.GetInt32(2);
            programId = reader.GetInt32(3);
        }

        var assignedUsers = new HashSet<int>();
        // Stable ordering and row locks serialize competing assignments. The entire request is atomic.
        foreach (var identifier in identifiers.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
        {
            int userId;
            await using (var user = new NpgsqlCommand(@"
                SELECT u.id FROM users u JOIN studentprofiles sp ON sp.user_id = u.id
                WHERE LOWER(u.role) = 'student' AND LOWER(u.status) = 'approved' AND u.is_active
                  AND (u.id::text = @identifier OR LOWER(sp.student_no) = LOWER(@identifier)
                       OR LOWER(u.email) = LOWER(@identifier) OR LOWER(sp.student_email) = LOWER(@identifier))
                FOR UPDATE OF u;", connection, transaction))
            {
                user.Parameters.AddWithValue("identifier", identifier);
                await using var reader = await user.ExecuteReaderAsync();
                if (!await reader.ReadAsync()) throw new InvalidOperationException($"Student '{identifier}' was not found or is inactive.");
                userId = reader.GetInt32(0);
                if (await reader.ReadAsync()) throw new InvalidOperationException($"Student identifier '{identifier}' is ambiguous. Use the student number.");
            }
            if (!assignedUsers.Add(userId)) continue;
            await using var update = new NpgsqlCommand(@"
                UPDATE student_enrollments
                SET academic_section_id = @sectionId, section = @section, updated_at = CURRENT_TIMESTAMP
                WHERE student_user_id = @userId AND school_year = @schoolYear AND semester = @semester
                  AND status = 'ENROLLED' AND program_id = @programId AND year_level = @yearLevel
                  AND (academic_section_id IS NULL OR academic_section_id = @sectionId)
                RETURNING enrollment_id;", connection, transaction);
            update.Parameters.AddWithValue("sectionId", sectionId);
            update.Parameters.AddWithValue("section", $"{yearLevel}-{sectionNumber}");
            update.Parameters.AddWithValue("userId", userId);
            update.Parameters.AddWithValue("schoolYear", schoolYear);
            update.Parameters.AddWithValue("semester", semester);
            update.Parameters.AddWithValue("programId", programId);
            update.Parameters.AddWithValue("yearLevel", yearLevel);
            var enrollmentId = await update.ExecuteScalarAsync();
            if (enrollmentId is null)
                throw new InvalidOperationException($"Student '{identifier}' needs an unassigned ENROLLED record for {schoolYear} {semester} in this program and year level. The student may already belong to another section.");

            // Assigning an older period must not replace the current profile snapshot.
            await using var profile = new NpgsqlCommand(@"
                UPDATE studentprofiles sp SET section = e.section, year_level = e.year_level::text,
                    department = p.program_name, curriculum_id = e.curriculum_id, batch_year = e.batch_year,
                    assignment_status = 'Enrolled'
                FROM student_enrollments e JOIN academic_programs p ON p.program_id = e.program_id
                WHERE e.enrollment_id = @enrollmentId AND sp.user_id = e.student_user_id
                  AND e.enrollment_id = (
                    SELECT latest.enrollment_id FROM student_enrollments latest
                    WHERE latest.student_user_id = e.student_user_id
                    ORDER BY latest.school_year DESC,
                        CASE latest.semester WHEN 'MIDYEAR' THEN 3 WHEN 'SECOND' THEN 2 ELSE 1 END DESC
                    LIMIT 1);", connection, transaction);
            profile.Parameters.AddWithValue("enrollmentId", Convert.ToInt64(enrollmentId));
            await profile.ExecuteNonQueryAsync();
        }
        await transaction.CommitAsync();
        return (assignedUsers.Count, department);
    }
}
