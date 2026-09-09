using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Npgsql;

namespace Client_app.Controllers;

[ApiController]
[Authorize(Roles = "registrar")]
[Route("api/password-reset-requests")]
public sealed class PasswordResetRequestsController : ControllerBase
{
    private readonly string _connectionString;

    public PasswordResetRequestsController(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("MasterConnection")
            ?? configuration.GetConnectionString("PostgresConnection")
            ?? throw new InvalidOperationException("A PostgreSQL write connection is required.");
    }

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(@"
            SELECT request_id, email, otp_code, expires_at, created_at,
                   CASE WHEN used_at IS NULL AND expires_at > @now THEN 'ACTIVE'
                        WHEN used_at IS NOT NULL THEN 'USED' ELSE 'EXPIRED' END
            FROM password_reset_requests
            WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
            ORDER BY created_at DESC;", connection);
        command.Parameters.AddWithValue("now", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var requests = new List<object>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            requests.Add(new
            {
                requestId = reader.GetInt64(0),
                email = reader.GetString(1),
                otp = reader.GetString(2),
                expiresAt = reader.GetInt64(3),
                createdAt = reader.GetFieldValue<DateTimeOffset>(4),
                status = reader.GetString(5)
            });
        }
        return Ok(new { status = "Success", data = requests });
    }
}