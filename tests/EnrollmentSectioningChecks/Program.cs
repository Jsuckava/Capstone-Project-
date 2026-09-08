using Client_app.Services;
using Npgsql;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

// Use a disposable database. This executable creates its own schema and removes only that schema.
var connectionString = Environment.GetEnvironmentVariable("SECTIONING_TEST_CONNECTION")
    ?? throw new Exception("Set SECTIONING_TEST_CONNECTION to a disposable PostgreSQL database.");
await using var connection = new NpgsqlConnection(connectionString);
await connection.OpenAsync();
var schema = "sectioning_test_" + Guid.NewGuid().ToString("N");
async Task Execute(string sql)
{
    await using var command = new NpgsqlCommand(sql, connection);
    await command.ExecuteNonQueryAsync();
}
async Task<object?> Scalar(string sql)
{
    await using var command = new NpgsqlCommand(sql, connection);
    return await command.ExecuteScalarAsync();
}
async Task Reject(Func<Task> action, string message)
{
    try { await action(); }
    catch (InvalidOperationException) { return; }
    catch (KeyNotFoundException) { return; }
    throw new Exception(message);
}

await Execute($"CREATE SCHEMA {schema}; SET search_path TO {schema};");
try
{
    await Execute(@"
        CREATE TABLE users (id INT PRIMARY KEY, email TEXT, role TEXT DEFAULT 'student',
            status TEXT DEFAULT 'APPROVED', is_active BOOLEAN DEFAULT TRUE);
        CREATE TABLE academic_programs (program_id INT PRIMARY KEY, program_code TEXT, program_name TEXT);
        CREATE TABLE curriculums (curriculum_id BIGINT PRIMARY KEY);
        CREATE TABLE studentprofiles (user_id INT PRIMARY KEY REFERENCES users(id), student_no TEXT,
            full_name TEXT, student_email TEXT, department TEXT, year_level TEXT, section TEXT,
            assignment_status TEXT, sex TEXT, curriculum_id BIGINT, batch_year INT);");
    await Execute(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment.sql")));
    await Execute("ALTER TABLE student_enrollments ADD COLUMN batch_year INT;");
    await Execute(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "lookup.sql")));
    await Execute(@"
        INSERT INTO academic_programs VALUES (1, 'BSIT', 'Information Technology'), (2, 'BSCS', 'Computer Science');
        INSERT INTO academicsections (id, department, year_level, section_num) VALUES
            (1, 'Information Technology', 1, 1), (2, 'BSIT', 1, 2),
            (3, 'Computer Science', 1, 1), (4, 'BSIT', 2, 1);
        INSERT INTO users (id, email) SELECT n, 'student' || n || '@test.invalid' FROM generate_series(1, 10) n;
        INSERT INTO studentprofiles (user_id, student_no, full_name, department, year_level, section, assignment_status)
            SELECT id, '26-' || LPAD(id::text, 4, '0'), 'Test Student ' || id, 'stale program', '4', '4-9', 'Dropped' FROM users;
        INSERT INTO student_enrollments (student_user_id, student_no, program_id, school_year, semester, year_level)
            SELECT id, '26-' || LPAD(id::text, 4, '0'), 1, '2026-2027', 'FIRST', 1 FROM users WHERE id < 10;
        UPDATE student_enrollments SET status = 'DROPPED' WHERE student_user_id = 2;
        UPDATE student_enrollments SET status = 'WITHDRAWN' WHERE student_user_id = 3;
        UPDATE student_enrollments SET status = 'COMPLETED' WHERE student_user_id = 4;
        UPDATE student_enrollments SET academic_section_id = 2, section = '1-2' WHERE student_user_id = 5;
        UPDATE student_enrollments SET program_id = 2 WHERE student_user_id = 6;
        UPDATE student_enrollments SET year_level = 2 WHERE student_user_id = 7;
        UPDATE users SET is_active = FALSE WHERE id = 8;
        INSERT INTO student_enrollments (student_user_id, student_no, program_id, school_year, semester, year_level)
            VALUES (1, '26-0001', 1, '2026-2027', 'SECOND', 2), (1, '26-0001', 1, '2025-2026', 'FIRST', 1);");

    var eligible = await EnrollmentSectioningService.GetUnassignedAsync(connection, "BSIT", 1, "2026-2027", "FIRST", null);
    Check(eligible.Select(student => student.Id).SequenceEqual(new[] { 1, 9 }), "Picker must use enrollment status, year and program, ignoring stale profiles.");
    Check(eligible.All(student => student.AcademicSectionId == null && student.EnrollmentStatus == "ENROLLED" && student.EnrollmentId > 0), "Enrollment status/FK defaults incorrect.");
    Check((await EnrollmentSectioningService.GetUnassignedAsync(connection, "BSIT", null, "2026-2027", "SECOND", null)).Count == 1, "Semester filter ignored.");
    Check((await EnrollmentSectioningService.GetUnassignedAsync(connection, null, null, "2025-2026", null, null)).Count == 1, "School-year filter ignored.");
    Check((await EnrollmentSectioningService.GetUnassignedAsync(connection, "BSCS", null, null, null, "BSIT")).Count == 0, "Department scope leaked.");
    Check((await EnrollmentSectioningService.GetUnassignedAsync(connection, null, null, null, null, null)).Count == 6, "Unfiltered query must return all eligible enrollment periods.");

    await Reject(() => EnrollmentSectioningService.AssignAsync(connection, 1, new[] { "26-0001", "26-0002" }, "2026-2027", "FIRST", null), "Dropped student accepted.");
    Check(await Scalar("SELECT academic_section_id FROM student_enrollments WHERE student_user_id = 1 AND school_year = '2026-2027' AND semester = 'FIRST'") == DBNull.Value, "Failed request partially committed.");
    foreach (var student in new[] { "26-0002", "26-0003", "26-0004", "26-0005", "26-0006", "26-0007", "26-0008", "26-0010", "missing" })
        await Reject(() => EnrollmentSectioningService.AssignAsync(connection, 1, new[] { student }, "2026-2027", "FIRST", null), $"Invalid assignment accepted: {student}");
    await Reject(() => EnrollmentSectioningService.AssignAsync(connection, 1, new[] { "26-0009" }, "2025-2026", "FIRST", null), "Missing period fabricated an enrollment.");
    await Reject(() => EnrollmentSectioningService.AssignAsync(connection, 3, new[] { "26-0006" }, "2026-2027", "FIRST", "BSIT"), "Cross-department assignment allowed.");

    var assigned = await EnrollmentSectioningService.AssignAsync(connection, 1, new[] { "26-0001", "26-0001", "1", "26-0009" }, "2026-2027", "FIRST", "BSIT");
    Check(assigned.Count == 2, "Duplicate student IDs/aliases counted more than once.");
    Check((await EnrollmentSectioningService.GetUnassignedAsync(connection, "BSIT", 1, "2026-2027", "FIRST", null)).Count == 0, "Assigned students still appear in picker.");
    Check(Convert.ToInt64(await Scalar("SELECT COUNT(*) FROM student_enrollments WHERE student_user_id = 1 AND academic_section_id IS NULL")) == 2, "Assignment changed other periods.");
    Check((string?)await Scalar("SELECT section FROM studentprofiles WHERE user_id = 1") == "4-9", "Older assignment overwrote the newer profile snapshot.");
    Check((string?)await Scalar("SELECT section FROM studentprofiles WHERE user_id = 9") == "1-1", "Current snapshot did not update.");
    Check((await EnrollmentSectioningService.AssignAsync(connection, 1, new[] { "26-0009" }, "2026-2027", "FIRST", null)).Count == 1, "Retry is not idempotent.");

    // Race two requests for the same unassigned enrollment; exactly one may win.
    await Execute("UPDATE student_enrollments SET academic_section_id = NULL, section = NULL WHERE student_user_id = 9;");
    async Task<bool> AssignConcurrent(int sectionId)
    {
        await using var other = new NpgsqlConnection(connectionString);
        await other.OpenAsync();
        await using (var searchPath = new NpgsqlCommand($"SET search_path TO {schema}", other)) await searchPath.ExecuteNonQueryAsync();
        try { await EnrollmentSectioningService.AssignAsync(other, sectionId, new[] { "26-0009" }, "2026-2027", "FIRST", null); return true; }
        catch (InvalidOperationException) { return false; }
    }
    var races = await Task.WhenAll(AssignConcurrent(1), AssignConcurrent(2));
    Check(races.Count(success => success) == 1, "Competing requests reassigned a student silently.");
    var previousSection = Convert.ToInt32(await Scalar("SELECT academic_section_id FROM student_enrollments WHERE student_user_id = 9"));
    var targetSection = previousSection == 1 ? 2 : 1;
    var expectedSections = new Dictionary<string, int> { ["26-0009"] = previousSection };
    await EnrollmentSectioningService.AssignAsync(connection, targetSection, new[] { "26-0009" }, "2026-2027", "FIRST", null, expectedSections);
    Check(Convert.ToInt32(await Scalar("SELECT academic_section_id FROM student_enrollments WHERE student_user_id = 9")) == targetSection,
        "An intentional move with the saved previous section was rejected.");
    await Reject(() => EnrollmentSectioningService.AssignAsync(connection, previousSection, new[] { "26-0009" }, "2026-2027", "FIRST", null,
        new Dictionary<string, int> { ["26-0009"] = 999 }), "Stale section move was accepted.");
    Console.WriteLine("PASS: schema defaults, authoritative period queries, scope, eligibility, atomic rollback, retries, snapshots, and concurrent assignment.");
}
finally
{
    await Execute($"DROP SCHEMA {schema} CASCADE;");
}
