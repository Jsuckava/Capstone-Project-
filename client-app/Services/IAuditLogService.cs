using Npgsql;

namespace Client_app.Services
{
    public interface IAuditLogService
    {
        Task LogAsync(
            string actorEmail,
            string actorRole,
            string action,
            string entityType,
            string entityId,
            object? oldValues = null,
            object? newValues = null,
            string? description = null,
            string? ipAddress = null,
            NpgsqlConnection? connection = null,
            NpgsqlTransaction? transaction = null,
            CancellationToken cancellationToken = default);
    }
}
