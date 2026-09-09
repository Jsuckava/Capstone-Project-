using System.Data;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Client_app.Services
{
    public sealed class AuditLogService : IAuditLogService
    {
        private readonly string _connectionString;

        public AuditLogService(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("MasterConnection")
                ?? configuration.GetConnectionString("PostgresConnection")
                ?? throw new InvalidOperationException("A PostgreSQL write connection is required.");
        }

        public async Task LogAsync(
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
            CancellationToken cancellationToken = default)
        {
            var ownsConnection = connection is null;
            connection ??= new NpgsqlConnection(_connectionString);
            if (connection.State != ConnectionState.Open)
            {
                await connection.OpenAsync(cancellationToken);
            }

            try
            {
                await using var command = new NpgsqlCommand(@"
                    INSERT INTO audit_logs
                        (user_id, actor_role, action, entity_type, entity_id, old_values, new_values, description, ip_address, timestamp)
                    VALUES
                        ((SELECT id FROM users WHERE LOWER(email) = LOWER(@actorEmail) LIMIT 1),
                         @actorRole, @action, @entityType, @entityId, @oldValues, @newValues,
                         @description, @ipAddress, CURRENT_TIMESTAMP);", connection, transaction);
                command.Parameters.AddWithValue("actorEmail", actorEmail);
                command.Parameters.AddWithValue("actorRole", actorRole);
                command.Parameters.AddWithValue("action", action);
                command.Parameters.AddWithValue("entityType", entityType);
                command.Parameters.AddWithValue("entityId", entityId);
                command.Parameters.AddWithValue("oldValues", oldValues is null ? DBNull.Value : JsonSerializer.Serialize(oldValues));
                command.Parameters.AddWithValue("newValues", newValues is null ? DBNull.Value : JsonSerializer.Serialize(newValues));
                command.Parameters.AddWithValue("description", (object?)description ?? DBNull.Value);
                command.Parameters.AddWithValue("ipAddress", (object?)ipAddress ?? DBNull.Value);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                if (ownsConnection)
                {
                    await connection.DisposeAsync();
                }
            }
        }
    }
}
