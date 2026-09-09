using System.Security.Claims;
using Client_app.Models;
using Client_app.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Npgsql;
using System.Security.Cryptography;

namespace Client_app.Controllers
{
    [ApiController]
    [Authorize(Roles = "registrar,system_admin")]
    [Route("api/[controller]")]
    public sealed class SupportTicketsController : ControllerBase
    {
        private static readonly HashSet<string> Statuses = new(StringComparer.OrdinalIgnoreCase) { "OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED" };
        private static readonly IReadOnlyDictionary<string, (string Label, string Scope)> Specialists =
            new Dictionary<string, (string Label, string Scope)>(StringComparer.OrdinalIgnoreCase)
            {
                ["IT_ADMIN"] = ("IT Admin", "Overall"),
                ["FRONTEND_DEVELOPER"] = ("Web Developer", "Frontend"),
                ["BACKEND_DEVELOPER"] = ("API Issues", "Backend Developer"),
                ["NETWORK_SPECIALIST"] = ("Network and Docker Issues", "Network Specialist")
            };
        private readonly string _connectionString;
        private readonly IAuditLogService _auditLog;
        private readonly IHubContext<ChatHub> _chatHubContext;

        public SupportTicketsController(IConfiguration configuration, IAuditLogService auditLog, IHubContext<ChatHub> chatHubContext)
        {
            _connectionString = configuration.GetConnectionString("MasterConnection")
                ?? configuration.GetConnectionString("PostgresConnection")
                ?? throw new InvalidOperationException("A PostgreSQL write connection is required.");
            _auditLog = auditLog;
            _chatHubContext = chatHubContext;
        }

        [HttpGet]
        public async Task<IActionResult> List(CancellationToken cancellationToken)
        {
            var role = ActorRole();
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = new NpgsqlCommand(@"
                SELECT t.ticket_id, t.title, t.description, t.severity, t.status, t.admin_response,
                       t.created_at, t.updated_at, t.resolved_at, registrar.email,
                       COALESCE(ap.full_name, registrar.email), t.assigned_specialist
                FROM support_tickets t
                JOIN users registrar ON registrar.id = t.registrar_id
                LEFT JOIN adminprofiles ap ON ap.user_id = registrar.id
                WHERE (@isAdmin OR LOWER(registrar.email) = LOWER(@actor))
                ORDER BY CASE t.status WHEN 'OPEN' THEN 1 WHEN 'IN_PROGRESS' THEN 2 ELSE 3 END,
                         t.created_at DESC;", connection);
            command.Parameters.AddWithValue("isAdmin", role == "system_admin");
            command.Parameters.AddWithValue("actor", ActorEmail());
            var tickets = new List<object>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var assignedSpecialist = reader.IsDBNull(11) ? null : reader.GetString(11);
                tickets.Add(new
                {
                    ticketId = reader.GetInt64(0), title = reader.GetString(1), description = reader.GetString(2),
                    severity = reader.GetString(3), status = reader.GetString(4),
                    adminResponse = reader.IsDBNull(5) ? null : reader.GetString(5),
                    createdAt = reader.GetFieldValue<DateTimeOffset>(6), updatedAt = reader.GetFieldValue<DateTimeOffset>(7),
                    resolvedAt = reader.IsDBNull(8) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(8),
                    registrarEmail = reader.GetString(9), registrarName = reader.GetString(10),
                    assignedSpecialist,
                    assignedSpecialistLabel = assignedSpecialist is not null && Specialists.TryGetValue(assignedSpecialist, out var specialist)
                        ? $"{specialist.Label} - {specialist.Scope}"
                        : null
                });
            }
            return Ok(new { status = "Success", data = tickets });
        }

        [HttpGet("specialists")]
        public IActionResult ListSpecialists()
        {
            var specialists = Specialists.Select(item => new
            {
                specialistId = item.Key,
                label = item.Value.Label,
                scope = item.Value.Scope
            }).ToList();
            return Ok(new { status = "Success", data = specialists });
        }

        [HttpPost("broadcast")]
        [Authorize(Roles = "system_admin")]
        public async Task<IActionResult> BroadcastNotice([FromBody] BroadcastSupportNoticeRequest request, CancellationToken cancellationToken)
        {
            var noticeId = $"{RandomLetter()}{RandomLetter()}{RandomNumberGenerator.GetInt32(100000):D5}";
            var customMessage = request.Message.Trim();
            var displayMessage = $"Notice - ({noticeId} - {customMessage})";
            var payload = new { noticeId, message = customMessage, displayMessage, createdAt = DateTimeOffset.UtcNow };

            await _auditLog.LogAsync(ActorEmail(), "system_admin", "SUPPORT_NOTICE_BROADCAST", "support_notice", noticeId, null,
                new { noticeId, messageLength = customMessage.Length }, "System Administrator broadcast a support resolution notice.",
                HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken: cancellationToken);
            await _chatHubContext.Clients.All.SendAsync("SupportNotice", payload, cancellationToken);

            return Ok(new { status = "Success", data = payload });
        }

        [HttpPost]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> Create([FromBody] CreateSupportTicketRequest request, CancellationToken cancellationToken)
        {
            var assignedSpecialist = NormalizeSpecialist(request.AssignedSpecialist);
            if (!Specialists.ContainsKey(assignedSpecialist))
                return BadRequest(new { status = "Error", message = "Select a valid support specialty." });
            var specialist = Specialists[assignedSpecialist];
            var title = $"{specialist.Label} support request";
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(@"
                INSERT INTO support_tickets (registrar_id, title, description, severity, assigned_specialist)
                SELECT id, @title, @description, 'NORMAL', @assignedSpecialist FROM users
                WHERE LOWER(email) = LOWER(@actor) AND LOWER(role) = 'registrar' AND is_active = TRUE
                RETURNING ticket_id;", connection, transaction);
            command.Parameters.AddWithValue("title", title);
            command.Parameters.AddWithValue("description", request.Description.Trim());
            command.Parameters.AddWithValue("assignedSpecialist", assignedSpecialist);
            command.Parameters.AddWithValue("actor", ActorEmail());
            var result = await command.ExecuteScalarAsync(cancellationToken);
            if (result is null) return Forbid();
            var ticketId = Convert.ToInt64(result);
            await _auditLog.LogAsync(ActorEmail(), "registrar", "SUPPORT_TICKET_CREATED", "support_ticket", ticketId.ToString(), null,
                new { title, severity = "NORMAL", status = "OPEN", assignedSpecialist }, "Registrar reported a system error to the System Administrator.",
                HttpContext.Connection.RemoteIpAddress?.ToString(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CreatedAtAction(nameof(List), new { id = ticketId }, new { status = "Success", data = new { ticketId } });
        }

        [HttpPut("{ticketId:long}")]
        [Authorize(Roles = "system_admin")]
        public async Task<IActionResult> Update(long ticketId, [FromBody] UpdateSupportTicketRequest request, CancellationToken cancellationToken)
        {
            var status = request.Status.Trim().ToUpperInvariant();
            if (!Statuses.Contains(status)) return BadRequest(new { status = "Error", message = "Invalid ticket status." });
            var assignedSpecialist = NormalizeSpecialist(request.AssignedSpecialist);
            if (!Specialists.ContainsKey(assignedSpecialist))
                return BadRequest(new { status = "Error", message = "Select a valid support specialist." });
            if (status is "RESOLVED" or "CLOSED" && string.IsNullOrWhiteSpace(request.AdminResponse))
                return BadRequest(new { status = "Error", message = "An administrator response is required to resolve or close a ticket." });
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

            await using var command = new NpgsqlCommand(@"
                UPDATE support_tickets
                SET status = @status, admin_response = @response,
                    assigned_specialist = @assignedSpecialist,
                    updated_at = CURRENT_TIMESTAMP,
                    resolved_at = CASE WHEN @status IN ('RESOLVED', 'CLOSED') THEN CURRENT_TIMESTAMP ELSE NULL END
                WHERE ticket_id = @ticketId RETURNING ticket_id;", connection, transaction);
            command.Parameters.AddWithValue("status", status);
            command.Parameters.AddWithValue("response", (object?)request.AdminResponse?.Trim() ?? DBNull.Value);
            command.Parameters.AddWithValue("assignedSpecialist", assignedSpecialist);
            command.Parameters.AddWithValue("ticketId", ticketId);
            if (await command.ExecuteScalarAsync(cancellationToken) is null) return NotFound(new { status = "Error", message = "Ticket not found." });
            await _auditLog.LogAsync(ActorEmail(), "system_admin", "SUPPORT_TICKET_UPDATED", "support_ticket", ticketId.ToString(), null,
                new { status, hasResponse = !string.IsNullOrWhiteSpace(request.AdminResponse), assignedSpecialist },
                "System Administrator updated and assigned a Registrar support ticket.",
                HttpContext.Connection.RemoteIpAddress?.ToString(), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Ok(new { status = "Success", message = "Ticket updated." });
        }

        private string ActorEmail() => User.Identity?.Name ?? throw new UnauthorizedAccessException("Authenticated identity is missing.");
        private static string NormalizeSpecialist(string value) => value.Trim().ToUpperInvariant();

        private static char RandomLetter() => (char)('A' + RandomNumberGenerator.GetInt32(26));

        private string ActorRole() => (User.Claims.FirstOrDefault(claim => claim.Type == "dbRole")?.Value
            ?? User.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Role)?.Value ?? string.Empty)
            .Trim().ToLowerInvariant().Replace('-', '_');
    }
}
