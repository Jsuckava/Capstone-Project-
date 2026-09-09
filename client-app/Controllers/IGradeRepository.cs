using BlockGo.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text.Json.Nodes;

namespace BlockGo.Repositories
{
    public interface IGradeRepository
    {
        Task<string?> GetFacultyDepartmentAsync(string email);
        Task<string?> GetStudentDepartmentAsync(string email);
        Task StageGradeAsync(AcademicRecord record, string newGrade, string reasonText);
        Task<int> SubmitSectionAsync(string facultyId, string section, string date);
        Task<(string? dept, string? email)> GetStudentInfoAsync(string studentId);
        Task<int> CreateStudentAsync(string email, string password, string studentNo, string course, string dob);
        Task BulkStageGradeAsync(AcademicRecord record, string newGrade, string reasonText);
        Task<string?> GetPendingGradeValueAsync(string recordId);
        Task UpdatePendingGradeValueAsync(string recordId, string newGrade, string date);
        Task LogGradeCorrectionAsync(string recordId, string? oldGrade, string? newGrade, string reasonText, string? approvedBy);
        Task<List<AcademicRecord>> GetAllPendingGradesAsync();
        Task<Dictionary<string, (string dept, string sec)>> GetStudentProfilesDictAsync();
        Task<AcademicRecord?> GetPendingGradeRecordAsync(string recordId);
        Task<string?> ApprovePendingGradeAsync(string recordId);
        Task DeletePendingGradeAsync(string recordId);
        Task<bool> UpdatePendingGradeJsonAsync(string recordId, Action<JsonObject> updateAction);
        Task<string?> GetChairpersonEmailAsync(string department);
        Task<string?> ReturnPendingGradeAsync(string recordId, string note, string date);
        Task<List<object>> GetAuditLogsAsync(string? recordId = null);
    }
}