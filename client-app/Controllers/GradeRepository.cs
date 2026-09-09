using BlockGo.Models;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text.Json.Nodes;

namespace BlockGo.Repositories
{
    public class GradeRepository : IGradeRepository
    {
        private readonly string _connectionString;

        public GradeRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? configuration.GetConnectionString("MasterConnection") ?? throw new InvalidOperationException("PostgreSQL connection string not found.");
        }

        public async Task<string?> GetFacultyDepartmentAsync(string email)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdFac = new NpgsqlCommand(@"
                SELECT department FROM (
                    SELECT fp.department FROM Users u JOIN FacultyProfiles fp ON u.id = fp.user_id WHERE u.email = @email AND u.status = 'APPROVED'
                    UNION 
                    SELECT ap.department FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id WHERE u.email = @email AND u.status = 'APPROVED'
                ) AS combined LIMIT 1", conn);
            cmdFac.Parameters.AddWithValue("email", email);
            return await cmdFac.ExecuteScalarAsync() as string;
        }

        public async Task<string?> GetStudentDepartmentAsync(string email)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdStu = new NpgsqlCommand("SELECT sp.department FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id WHERE u.email = @email AND u.role = 'student'", conn);
            cmdStu.Parameters.AddWithValue("email", email);
            return await cmdStu.ExecuteScalarAsync() as string;
        }

        public async Task StageGradeAsync(AcademicRecord blockchainRecord, string newGrade, string reasonText)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var transaction = await conn.BeginTransactionAsync();
            try
            {
                using var cmdStage = new NpgsqlCommand(@"
                    WITH updated AS (
                        UPDATE pending_grade_records
                        SET section = @sec,
                            course = @course,
                            grade = @gr,
                            faculty_id = @fac,
                            date = @dt,
                            ipfs_cid = COALESCE(NULLIF(@ipfs, ''), ipfs_cid),
                            status = 'Issued'
                        WHERE student_hash = @sh
                          AND subject_code = @subj
                          AND school_year = @sy
                          AND semester = @sem
                        RETURNING id
                    )
                    INSERT INTO pending_grade_records (id, student_hash, section, course, subject_code, grade, semester, school_year, faculty_id, date, ipfs_cid, status)
                    SELECT @id, @sh, @sec, @course, @subj, @gr, @sem, @sy, @fac, @dt, @ipfs, 'Issued'
                    WHERE NOT EXISTS (SELECT 1 FROM updated)
                    ON CONFLICT (id) DO UPDATE SET
                        grade = EXCLUDED.grade,
                        status = 'Issued',
                        date = EXCLUDED.date;", conn, transaction);
                cmdStage.Parameters.AddWithValue("id", blockchainRecord.Id ?? (object)Guid.NewGuid().ToString());
                cmdStage.Parameters.AddWithValue("sh", blockchainRecord.StudentHash ?? "");
                cmdStage.Parameters.AddWithValue("sec", blockchainRecord.Section ?? "");
                cmdStage.Parameters.AddWithValue("course", blockchainRecord.Course ?? "");
                cmdStage.Parameters.AddWithValue("subj", blockchainRecord.SubjectCode ?? "");
                cmdStage.Parameters.AddWithValue("gr", blockchainRecord.Grade ?? "");
                cmdStage.Parameters.AddWithValue("sem", blockchainRecord.Semester ?? "");
                cmdStage.Parameters.AddWithValue("sy", blockchainRecord.SchoolYear ?? "");
                cmdStage.Parameters.AddWithValue("fac", blockchainRecord.FacultyId ?? "");
                cmdStage.Parameters.AddWithValue("dt", blockchainRecord.Date ?? "");
                cmdStage.Parameters.AddWithValue("ipfs", blockchainRecord.IpfsCid ?? "");
                await cmdStage.ExecuteNonQueryAsync();

                using var cmdLog = new NpgsqlCommand(@"
                    INSERT INTO gradecorrectionlogs (recordid, oldgrade, newgrade, reasontext, approvedby, timestamp) 
                    VALUES (@rid, @old, @new, @reason, @appr, CURRENT_TIMESTAMP)", conn, transaction);
                cmdLog.Parameters.AddWithValue("rid", blockchainRecord.Id ?? (object)Guid.NewGuid().ToString());
                cmdLog.Parameters.AddWithValue("old", DBNull.Value);
                cmdLog.Parameters.AddWithValue("new", newGrade);
                cmdLog.Parameters.AddWithValue("reason", reasonText);
                cmdLog.Parameters.AddWithValue("appr", blockchainRecord.FacultyId ?? (object)DBNull.Value);
                await cmdLog.ExecuteNonQueryAsync();

                await transaction.CommitAsync();
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        public async Task<int> SubmitSectionAsync(string facultyId, string section, string date)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            using var cmd = new NpgsqlCommand(@"
                UPDATE pending_grade_records
                SET status = 'Issued', date = @date
                WHERE faculty_id = @faculty
                  AND (
                    section = @section
                    OR subject_code = @section
                    OR course = @section
                    OR (COALESCE(section, '') <> '' AND @section ILIKE '%' || section || '%')
                    OR (COALESCE(subject_code, '') <> '' AND @section ILIKE '%' || subject_code || '%')
                  )", conn);
            cmd.Parameters.AddWithValue("faculty", facultyId);
            cmd.Parameters.AddWithValue("section", section);
            cmd.Parameters.AddWithValue("date", date);

            return await cmd.ExecuteNonQueryAsync();
        }

        public async Task<(string? dept, string? email)> GetStudentInfoAsync(string studentId)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdStu = new NpgsqlCommand("SELECT sp.department, u.email FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id WHERE (sp.student_no = @sid OR u.email = @sid) AND u.role = 'student'", conn);
            cmdStu.Parameters.AddWithValue("sid", studentId);
            string? stuDept = null, stuEmail = null;
            using (var reader = await cmdStu.ExecuteReaderAsync())
            {
                if (await reader.ReadAsync())
                {
                    stuDept = reader.IsDBNull(0) ? null : reader.GetString(0);
                    stuEmail = reader.GetString(1);
                }
            }
            return (stuDept, stuEmail);
        }

        public async Task<int> CreateStudentAsync(string email, string password, string studentNo, string course, string dob)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var txCreate = await conn.BeginTransactionAsync();
            try 
            {
                using var cmdUser = new NpgsqlCommand("INSERT INTO Users (email, password_hash, role, status) VALUES (@email, crypt(@password, gen_salt('bf', 12)), 'student', 'APPROVED') RETURNING id", conn, txCreate);
                cmdUser.Parameters.AddWithValue("email", email);
                cmdUser.Parameters.AddWithValue("password", password);
                int newUserId = (int)(await cmdUser.ExecuteScalarAsync() ?? throw new Exception("Failed to get ID"));

                using var cmdProfile = new NpgsqlCommand(@"
                    INSERT INTO StudentProfiles (user_id, full_name, student_no, department, section, date_of_birth, assignment_status) 
                    VALUES (@uid, @name, @studentno, @dept, @sec, @dob, 'Enrolled')", conn, txCreate);
                cmdProfile.Parameters.AddWithValue("uid", newUserId);
                cmdProfile.Parameters.AddWithValue("name", "Student " + (studentNo ?? ""));
                cmdProfile.Parameters.AddWithValue("studentno", (object?)studentNo ?? DBNull.Value);
                cmdProfile.Parameters.AddWithValue("dept", course ?? "Unassigned");
                cmdProfile.Parameters.AddWithValue("sec", DBNull.Value);
                cmdProfile.Parameters.AddWithValue("dob", DateTime.Parse(dob));
                await cmdProfile.ExecuteNonQueryAsync();
                
                await txCreate.CommitAsync();
                return newUserId;
            }
            catch {
                await txCreate.RollbackAsync();
                throw;
            }
        }

        public async Task BulkStageGradeAsync(AcademicRecord record, string newGrade, string reasonText)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var transaction = await conn.BeginTransactionAsync();
            try
            {
                using var cmdStage = new NpgsqlCommand(@"
                    INSERT INTO pending_grade_records (id, student_hash, section, course, subject_code, grade, semester, school_year, faculty_id, date, ipfs_cid, status)
                    VALUES (@id, @sh, @sec, @course, @subj, @gr, @sem, @sy, @fac, @dt, @ipfs, 'Issued')
                    ON CONFLICT (id) DO UPDATE SET grade = EXCLUDED.grade, status = 'Issued', ipfs_cid = EXCLUDED.ipfs_cid, date = EXCLUDED.date;", conn, transaction);
                cmdStage.Parameters.AddWithValue("id", record.Id ?? Guid.NewGuid().ToString());
                cmdStage.Parameters.AddWithValue("sh", record.StudentHash ?? "");
                cmdStage.Parameters.AddWithValue("sec", record.Section ?? "");
                cmdStage.Parameters.AddWithValue("course", record.Course ?? "");
                cmdStage.Parameters.AddWithValue("subj", record.SubjectCode ?? "");
                cmdStage.Parameters.AddWithValue("gr", record.Grade ?? "");
                cmdStage.Parameters.AddWithValue("sem", record.Semester ?? "");
                cmdStage.Parameters.AddWithValue("sy", record.SchoolYear ?? "");
                cmdStage.Parameters.AddWithValue("fac", record.FacultyId ?? "");
                cmdStage.Parameters.AddWithValue("dt", record.Date ?? "");
                cmdStage.Parameters.AddWithValue("ipfs", record.IpfsCid ?? "");
                await cmdStage.ExecuteNonQueryAsync();

                using var cmdLog = new NpgsqlCommand(@"
                    INSERT INTO gradecorrectionlogs (recordid, oldgrade, newgrade, reasontext, approvedby, timestamp) 
                    VALUES (@rid, @old, @new, @reason, @appr, CURRENT_TIMESTAMP)", conn, transaction);
                cmdLog.Parameters.AddWithValue("rid", record.Id ?? "");
                cmdLog.Parameters.AddWithValue("old", (object)DBNull.Value);
                cmdLog.Parameters.AddWithValue("new", newGrade);
                cmdLog.Parameters.AddWithValue("reason", reasonText);
                cmdLog.Parameters.AddWithValue("appr", record.FacultyId ?? (object)DBNull.Value);
                await cmdLog.ExecuteNonQueryAsync();
                
                await transaction.CommitAsync();
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        public async Task<string?> GetPendingGradeValueAsync(string recordId)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdCheck = new NpgsqlCommand("SELECT grade FROM pending_grade_records WHERE id = @id", conn);
            cmdCheck.Parameters.AddWithValue("id", recordId);
            return await cmdCheck.ExecuteScalarAsync() as string;
        }

        public async Task UpdatePendingGradeValueAsync(string recordId, string newGrade, string date)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdUpdate = new NpgsqlCommand("UPDATE pending_grade_records SET grade = @grade, status = 'Corrected', date = @dt WHERE id = @id", conn);
            cmdUpdate.Parameters.AddWithValue("grade", newGrade);
            cmdUpdate.Parameters.AddWithValue("dt", date);
            cmdUpdate.Parameters.AddWithValue("id", recordId);
            await cmdUpdate.ExecuteNonQueryAsync();
        }

        public async Task LogGradeCorrectionAsync(string recordId, string? oldGrade, string? newGrade, string reasonText, string? approvedBy)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdLog = new NpgsqlCommand(@"
                INSERT INTO gradecorrectionlogs (recordid, oldgrade, newgrade, reasontext, approvedby, timestamp) 
                VALUES (@rid, @old, @new, @reason, @appr, CURRENT_TIMESTAMP)", conn);
            cmdLog.Parameters.AddWithValue("rid", recordId ?? (object)DBNull.Value);
            cmdLog.Parameters.AddWithValue("old", oldGrade != null ? (object)oldGrade : DBNull.Value);
            cmdLog.Parameters.AddWithValue("new", newGrade != null ? (object)newGrade : DBNull.Value);
            cmdLog.Parameters.AddWithValue("reason", reasonText ?? "");
            cmdLog.Parameters.AddWithValue("appr", approvedBy ?? "");
            await cmdLog.ExecuteNonQueryAsync();
        }

        public async Task<List<AcademicRecord>> GetAllPendingGradesAsync()
        {
            var allGrades = new List<AcademicRecord>();
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            
            using var cmd = new NpgsqlCommand("SELECT id, student_hash, section, course, subject_code, grade, semester, school_year, faculty_id, date, ipfs_cid, status, note FROM pending_grade_records", conn);
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                allGrades.Add(new AcademicRecord {
                    Id = reader.IsDBNull(0) ? "" : reader.GetString(0),
                    StudentHash = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    Section = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Course = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    SubjectCode = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    Grade = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    Semester = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    SchoolYear = reader.IsDBNull(7) ? "" : reader.GetString(7),
                    FacultyId = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    Date = reader.IsDBNull(9) ? "" : reader.GetString(9),
                    IpfsCid = reader.IsDBNull(10) ? "" : reader.GetString(10),
                    Status = reader.IsDBNull(11) ? "" : reader.GetString(11),
                    Note = reader.IsDBNull(12) ? "" : reader.GetString(12),
                    University = "PLV",
                    Version = 1
                });
            }
            return allGrades;
        }

        public async Task<Dictionary<string, (string dept, string sec)>> GetStudentProfilesDictAsync()
        {
            var studentProfiles = new Dictionary<string, (string dept, string sec)>();
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdProfiles = new NpgsqlCommand("SELECT u.email, sp.department, sp.section FROM Users u JOIN StudentProfiles sp ON u.id = sp.user_id", conn);
            using var profReader = await cmdProfiles.ExecuteReaderAsync();
            while (await profReader.ReadAsync())
            {
                studentProfiles[profReader.GetString(0)] = (
                    profReader.IsDBNull(1) ? "Unknown" : profReader.GetString(1),
                    profReader.IsDBNull(2) ? "Unknown" : profReader.GetString(2)
                );
            }
            return studentProfiles;
        }

        public async Task<AcademicRecord?> GetPendingGradeRecordAsync(string recordId)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmd = new NpgsqlCommand("SELECT id, student_hash, section, course, subject_code, grade, semester, school_year, faculty_id, date, ipfs_cid, status, note FROM pending_grade_records WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("id", recordId);
            
            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new AcademicRecord {
                    Id = reader.IsDBNull(0) ? "" : reader.GetString(0),
                    StudentHash = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    Section = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Course = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    SubjectCode = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    Grade = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    Semester = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    SchoolYear = reader.IsDBNull(7) ? "" : reader.GetString(7),
                    FacultyId = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    Date = reader.IsDBNull(9) ? "" : reader.GetString(9),
                    IpfsCid = reader.IsDBNull(10) ? "" : reader.GetString(10),
                    Status = reader.IsDBNull(11) ? "" : reader.GetString(11),
                    Note = reader.IsDBNull(12) ? "" : reader.GetString(12),
                    University = "PLV",
                    Version = 1
                };
            }
            return null;
        }

        public async Task<string?> ApprovePendingGradeAsync(string recordId)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmd = new NpgsqlCommand("UPDATE pending_grade_records SET status = 'DepartmentApproved' WHERE id = @id RETURNING id", conn);
            cmd.Parameters.AddWithValue("id", recordId);
            return await cmd.ExecuteScalarAsync() as string;
        }

        public async Task DeletePendingGradeAsync(string recordId)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdDel = new NpgsqlCommand("DELETE FROM pending_grade_records WHERE id = @id", conn);
            cmdDel.Parameters.AddWithValue("id", recordId);
            await cmdDel.ExecuteNonQueryAsync();
        }

        public async Task<bool> UpdatePendingGradeJsonAsync(string recordId, Action<JsonObject> updateAction)
        {
            try {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmdSel = new NpgsqlCommand("SELECT grade FROM pending_grade_records WHERE id = @id", conn);
                cmdSel.Parameters.AddWithValue("id", recordId);
                var existingGrade = await cmdSel.ExecuteScalarAsync() as string;
                
                if (existingGrade == null) return false;
                
                JsonObject gradeObj;
                if (existingGrade.TrimStart().StartsWith("{")) {
                    try { gradeObj = System.Text.Json.Nodes.JsonNode.Parse(existingGrade)?.AsObject() ?? new JsonObject(); }
                    catch { gradeObj = new JsonObject(); gradeObj["finalAverage"] = existingGrade; }
                } else {
                    gradeObj = new JsonObject(); gradeObj["finalAverage"] = existingGrade;
                }
                
                updateAction(gradeObj);
                
                using var cmdUpd = new NpgsqlCommand("UPDATE pending_grade_records SET grade = @gr, date = @dt WHERE id = @id", conn);
                cmdUpd.Parameters.AddWithValue("gr", gradeObj.ToJsonString());
                cmdUpd.Parameters.AddWithValue("dt", DateTime.UtcNow.ToString("yyyy-MM-dd"));
                cmdUpd.Parameters.AddWithValue("id", recordId);
                await cmdUpd.ExecuteNonQueryAsync();
                
                return true;
            } catch { return false; }
        }

        public async Task<string?> GetChairpersonEmailAsync(string department)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmdChair = new NpgsqlCommand("SELECT u.email FROM Users u JOIN AdminProfiles ap ON u.id = ap.user_id WHERE ap.department = @dept AND u.role IN ('department_admin', 'deptAdmin') AND u.status = 'APPROVED' LIMIT 1", conn);
            cmdChair.Parameters.AddWithValue("dept", department);
            return await cmdChair.ExecuteScalarAsync() as string;
        }

        public async Task<string?> ReturnPendingGradeAsync(string recordId, string note, string date)
        {
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmd = new NpgsqlCommand("UPDATE pending_grade_records SET status = 'Returned', note = @note, date = @dt WHERE id = @id RETURNING id", conn);
            cmd.Parameters.AddWithValue("note", note);
            cmd.Parameters.AddWithValue("dt", date);
            cmd.Parameters.AddWithValue("id", recordId);
            return await cmd.ExecuteScalarAsync() as string;
        }

        public async Task<List<object>> GetAuditLogsAsync(string? recordId = null)
        {
            var logs = new List<object>();
            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            string query = @"
                SELECT logid, recordid, oldgrade, newgrade, reasontext, approvedby, timestamp 
                FROM gradecorrectionlogs ";
            
            if (recordId != null) query += " WHERE recordid = @rid ";
            query += " ORDER BY timestamp DESC";

            using var cmd = new NpgsqlCommand(query, conn);
            if (recordId != null) cmd.Parameters.AddWithValue("rid", recordId);
            
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                logs.Add(new {
                    id = reader.GetInt32(0),
                    recordId = reader.GetString(1),
                    oldGrade = reader.IsDBNull(2) ? null : reader.GetString(2),
                    newGrade = reader.IsDBNull(3) ? null : reader.GetString(3),
                    reason = reader.IsDBNull(4) ? null : reader.GetString(4),
                    approvedBy = reader.IsDBNull(5) ? null : reader.GetString(5),
                    timestamp = reader.GetDateTime(6)
                });
            }
            return logs;
        }
    }
}
