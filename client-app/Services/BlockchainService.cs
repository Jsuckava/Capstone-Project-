using BlockGo.Models;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;

namespace BlockGo.Services
{
    public class BlockchainService : IBlockchainService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<BlockchainService>? _logger;
        private readonly string _middlewareBaseUrl;

        public BlockchainService(HttpClient httpClient, IConfiguration configuration, ILogger<BlockchainService>? logger = null)
        {
            _httpClient = httpClient;
            _logger = logger;
            _middlewareBaseUrl = configuration["Middleware:Url"] ?? throw new InvalidOperationException("Middleware URL not configured in appsettings.json.");
            
            var apiKey = configuration["InternalApiKey"] ?? throw new InvalidOperationException("Internal API Key not configured.");
            _httpClient.DefaultRequestHeaders.Add("x-api-key", apiKey);
        }

        public async Task<string> GetAllGradesAsync(string invokerUsername)
        {
            _logger?.LogInformation("Getting all grades from blockchain as {User}", invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Get, $"{_middlewareBaseUrl}/api/all-grades");
            request.Headers.Add("x-user-identity", invokerUsername); 

            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware GetAllGrades Error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> GetStudentTransactionsAsync(string studentUsername)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"{_middlewareBaseUrl}/api/student-transactions");
            request.Headers.Add("x-user-identity", studentUsername);
            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware student transaction history error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> GetGradeHistoryAsync(string recordId, string invokerUsername)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"{_middlewareBaseUrl}/api/grade-history/{Uri.EscapeDataString(recordId)}");
            request.Headers.Add("x-user-identity", invokerUsername);
            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new Exception($"Middleware Error: {errorContent}");
            }
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> RecordAuditEventAsync(BlockchainAuditEvent auditEvent, string invokerUsername)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/fabric/audit-event")
            {
                Content = JsonContent.Create(auditEvent)
            };
            request.Headers.Add("x-user-identity", invokerUsername);
            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware audit event error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> GetGradeAsync(string recordId, string invokerUsername)
        {
            _logger?.LogInformation("Getting grade for record: {RecordId} as {User}", recordId, invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Get, $"{_middlewareBaseUrl}/api/get-grade/{recordId}");
            request.Headers.Add("x-user-identity", invokerUsername); 

            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware GetGrade Error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> SubmitGradeAsync(AcademicRecord record, string invokerUsername)
        {
            _logger?.LogInformation("Submitting grade for student: {StudentId} as {User}", record.Id, invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/issue-grade")
            {
                Content = JsonContent.Create(record)
            };
            request.Headers.Add("x-user-identity", invokerUsername);
            
            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware Issue Error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> SubmitBatchGradesAsync(IEnumerable<AcademicRecord> records, string invokerUsername)
        {
            _logger?.LogInformation("Submitting batch grades ({Count} records) as {User}", records.Count(), invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/batch-issue-grade")
            {
                Content = JsonContent.Create(records)
            };
            request.Headers.Add("x-user-identity", invokerUsername);
            
            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware Batch Error: {Error}", errorContent);
                throw new Exception($"Middleware Batch Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> UpdateGradeAsync(AcademicRecord record, string invokerUsername)
        {
            _logger?.LogInformation("Updating grade for student: {StudentId} as {User}", record.Id, invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/update-grade")
            {
                Content = JsonContent.Create(record)
            };
            request.Headers.Add("x-user-identity", invokerUsername);
            
            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware UpdateGrade Error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> ReturnGradeAsync(string recordId, string note, string invokerUsername)
        {
            _logger?.LogInformation("Returning record: {RecordId} for revision as {User}", recordId, invokerUsername);

            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/return-grade/{recordId}")
            {
                Content = JsonContent.Create(new { note })
            };
            request.Headers.Add("x-user-identity", invokerUsername);

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware Return Error: {Error}", errorContent);
                throw new Exception($"Middleware Return Error: {errorContent}");
            }

            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> ApproveGradeAsync(string recordId, string invokerUsername)
        {
            _logger?.LogInformation("Approving grade for record: {RecordId} as {User}", recordId, invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/approve-grade/{recordId}")
            {
                Content = JsonContent.Create(new { })
            };
            request.Headers.Add("x-user-identity", invokerUsername);

            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware Approve Error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> FinalizeGradeAsync(string recordId, string invokerUsername)
        {
            _logger?.LogInformation("Finalizing grade for record: {RecordId} as {User}", recordId, invokerUsername);
            
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/finalize-grade/{recordId}")
            {
                Content = JsonContent.Create(new { })
            };
            request.Headers.Add("x-user-identity", invokerUsername);

            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger?.LogError("Middleware Finalize Error: {Error}", errorContent);
                throw new Exception($"Middleware Error: {errorContent}");
            }
            
            return await response.Content.ReadAsStringAsync();
        }
    }
}
