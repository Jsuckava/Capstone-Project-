using BlockGo.Models;
using System.Threading.Tasks;

namespace BlockGo.Services
{
    public interface IBlockchainService
    {
        Task<string> SubmitGradeAsync(AcademicRecord record, string invokerUsername); 
        Task<string> SubmitBatchGradesAsync(IEnumerable<AcademicRecord> records, string invokerUsername);
        Task<string> UpdateGradeAsync(AcademicRecord record, string invokerUsername);
        Task<string> ReturnGradeAsync(string recordId, string note, string invokerUsername);
        Task<string> GetGradeAsync(string recordId, string invokerUsername);
        Task<string> GetAllGradesAsync(string invokerUsername);
        Task<string> GetStudentTransactionsAsync(string studentUsername);
        Task<string> GetGradeHistoryAsync(string recordId, string invokerUsername);
        Task<string> RecordAuditEventAsync(BlockchainAuditEvent auditEvent, string invokerUsername);
        Task<string> ApproveGradeAsync(string recordId, string invokerUsername);
        Task<string> FinalizeGradeAsync(string recordId, string invokerUsername);
    }
}
