using System.Net.Http.Json;
using System.Security.Cryptography;
using BlockGo.Models;
using BlockGo.Services;
using Client_app.Models;
using Npgsql;

namespace Client_app.Services
{
    public sealed class AccountProvisioningService : IAccountProvisioningService
    {
        private const int MaximumRegistrarAccounts = 2;
        private const long RegistrarCapacityLockId = 2026082802;
        private readonly string _connectionString;
        private readonly string _middlewareBaseUrl;
        private readonly string _internalApiKey;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAuditLogService _auditLog;
        private readonly IBlockchainService _blockchain;
        private readonly ILogger<AccountProvisioningService> _logger;

        public AccountProvisioningService(
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory,
            IAuditLogService auditLog,
            IBlockchainService blockchain,
            ILogger<AccountProvisioningService> logger)
        {
            _connectionString = configuration.GetConnectionString("MasterConnection")
                ?? configuration.GetConnectionString("PostgresConnection")
                ?? throw new InvalidOperationException("A PostgreSQL write connection is required.");
            _middlewareBaseUrl = configuration["Middleware:Url"]
                ?? throw new InvalidOperationException("Middleware URL is not configured.");
            _internalApiKey = configuration["InternalApiKey"]
                ?? throw new InvalidOperationException("Internal API key is not configured.");
            _httpClientFactory = httpClientFactory;
            _auditLog = auditLog;
            _blockchain = blockchain;
            _logger = logger;
        }

        public async Task<ManagedAccountResult> CreateStaffAsync(
            StaffAccountRequest request,
            string actorEmail,
            string? ipAddress,
            CancellationToken cancellationToken)
        {
            var role = NormalizeStaffRole(request.Role);
            var email = request.Email.Trim().ToLowerInvariant();
            var staffId = request.StaffId.Trim();
            var fullName = string.Join(" ", new[] { request.FirstName, request.MiddleName, request.LastName }
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!.Trim()));

            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

            var program = await ResolveProgramAsync(connection, transaction, request.ProgramCode, cancellationToken);
            await EnsureUniqueAccountAsync(connection, transaction, email, staffId, cancellationToken);
            if (role == "department_admin")
            {
                await EnsureDepartmentHasNoActiveChairAsync(connection, transaction, program.Name, program.Code, cancellationToken);
            }

            await RegisterFabricIdentityAsync(email, BuildEnrollmentSecret(email), role, cancellationToken);

            int userId;
            await using (var command = new NpgsqlCommand(@"
                INSERT INTO users (username, email, password_hash, role, organization, status, is_active, created_at, updated_at)
                VALUES (@staffId, @email, crypt(@password, gen_salt('bf')), @role, @organization, 'APPROVED', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                RETURNING id;", connection, transaction))
            {
                command.Parameters.AddWithValue("staffId", staffId);
                command.Parameters.AddWithValue("email", email);
                command.Parameters.AddWithValue("password", request.Password);
                command.Parameters.AddWithValue("role", role);
                command.Parameters.AddWithValue("organization", program.Code);
                userId = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            }

            if (role == "faculty")
            {
                await using var profile = new NpgsqlCommand(@"
                    INSERT INTO facultyprofiles (user_id, faculty_id, full_name, department, faculty_type)
                    VALUES (@userId, @staffId, @fullName, @department, @facultyType);", connection, transaction);
                profile.Parameters.AddWithValue("userId", userId);
                profile.Parameters.AddWithValue("staffId", staffId);
                profile.Parameters.AddWithValue("fullName", fullName);
                profile.Parameters.AddWithValue("department", program.Name);
                profile.Parameters.AddWithValue("facultyType", (object?)request.FacultyType?.Trim() ?? "Regular");
                await profile.ExecuteNonQueryAsync(cancellationToken);
            }
            else
            {
                await using var profile = new NpgsqlCommand(@"
                    INSERT INTO adminprofiles (user_id, full_name, admin_level, department)
                    VALUES (@userId, @fullName, 'department_admin', @department);", connection, transaction);
                profile.Parameters.AddWithValue("userId", userId);
                profile.Parameters.AddWithValue("fullName", fullName);
                profile.Parameters.AddWithValue("department", program.Name);
                await profile.ExecuteNonQueryAsync(cancellationToken);
            }

            await _auditLog.LogAsync(
                actorEmail, "registrar", role == "faculty" ? "FACULTY_ACCOUNT_CREATED" : "CHAIRPERSON_ACCOUNT_CREATED",
                "user", userId.ToString(), null,
                new { accountId = staffId, email, role, program = program.Code, status = "APPROVED" },
                $"Registrar created a {role} account.", ipAddress, connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return new ManagedAccountResult(userId, staffId, fullName, email, role, "APPROVED", true, program.Name, true);
        }

        public async Task<IReadOnlyCollection<ManagedAccountResult>> GetRegistrarsAsync(CancellationToken cancellationToken)
        {
            var accounts = new List<ManagedAccountResult>();
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = new NpgsqlCommand(@"
                SELECT u.id, COALESCE(u.username, u.id::text), COALESCE(ap.full_name, u.email),
                       u.email, u.role, u.status, u.is_active, ap.department
                FROM users u
                LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                WHERE LOWER(u.role) = 'registrar'
                ORDER BY u.created_at DESC, u.id DESC;", connection);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                accounts.Add(new ManagedAccountResult(
                    reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetBoolean(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7), true));
            }
            return accounts;
        }

        public async Task<ManagedAccountResult> CreateRegistrarAsync(
            RegistrarAccountRequest request,
            string actorEmail,
            string? ipAddress,
            CancellationToken cancellationToken)
        {
            var email = request.Email.Trim().ToLowerInvariant();
            var accountId = request.RegistrarId.Trim();
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await EnsureRegistrarCapacityAsync(connection, transaction, cancellationToken);
            await EnsureUniqueAccountAsync(connection, transaction, email, accountId, cancellationToken);
            await RegisterFabricIdentityAsync(email, BuildEnrollmentSecret(email), "registrar", cancellationToken);

            int userId;
            await using (var command = new NpgsqlCommand(@"
                INSERT INTO users (username, email, password_hash, role, organization, status, is_active, created_at, updated_at)
                VALUES (@accountId, @email, crypt(@password, gen_salt('bf')), 'registrar', 'Registrar', 'APPROVED', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                RETURNING id;", connection, transaction))
            {
                command.Parameters.AddWithValue("accountId", accountId);
                command.Parameters.AddWithValue("email", email);
                command.Parameters.AddWithValue("password", request.Password);
                userId = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            }
            await using (var profile = new NpgsqlCommand(@"
                INSERT INTO adminprofiles (user_id, full_name, admin_level, department)
                VALUES (@userId, @fullName, 'registrar', 'Registrar');", connection, transaction))
            {
                profile.Parameters.AddWithValue("userId", userId);
                profile.Parameters.AddWithValue("fullName", request.FullName.Trim());
                await profile.ExecuteNonQueryAsync(cancellationToken);
            }
            await _auditLog.LogAsync(actorEmail, "system_admin", "REGISTRAR_ACCOUNT_CREATED", "user", userId.ToString(), null,
                new { accountId, email, role = "registrar", status = "APPROVED", isActive = true },
                "System Administrator created a Registrar account.", ipAddress, connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            var ledgerRecorded = await TryRecordRegistrarAuditAsync(
                "REGISTRAR_ACCOUNT_CREATED", email, accountId, actorEmail, new[] { "email", "role", "status", "is_active" },
                "System Administrator created a Registrar account.", cancellationToken);
            return new ManagedAccountResult(userId, accountId, request.FullName.Trim(), email, "registrar", "APPROVED", true, "Registrar", ledgerRecorded,
                ledgerRecorded ? null : "The account was created, but the immutable audit event could not be recorded.");
        }

        public async Task<ManagedAccountResult> UpdateRegistrarAsync(
            int userId,
            UpdateRegistrarAccountRequest request,
            string actorEmail,
            string? ipAddress,
            CancellationToken cancellationToken)
        {
            if (request.Email is null && request.Password is null && request.IsActive is null)
            {
                throw new ArgumentException("At least one Registrar account field must be supplied.");
            }

            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            var existing = await GetRegistrarForUpdateAsync(connection, transaction, userId, cancellationToken);
            var newEmail = string.IsNullOrWhiteSpace(request.Email) ? existing.Email : request.Email.Trim().ToLowerInvariant();
            var changedFields = new List<string>();
            var emailChanged = !string.Equals(newEmail, existing.Email, StringComparison.OrdinalIgnoreCase);

            if (emailChanged)
            {
                await EnsureEmailAvailableAsync(connection, transaction, newEmail, userId, cancellationToken);
                await RegisterFabricIdentityAsync(newEmail, BuildEnrollmentSecret(newEmail), "registrar", cancellationToken);
                changedFields.Add("email");
            }
            else if (request.IsActive == true && !existing.IsActive)
            {
                // Deactivation removes the server-side wallet. Recreate it from
                // the existing CA identity before database access is restored.
                await RegisterFabricIdentityAsync(newEmail, BuildEnrollmentSecret(newEmail), "registrar", cancellationToken);
            }
            if (!string.IsNullOrWhiteSpace(request.Password)) changedFields.Add("password");
            if (request.IsActive.HasValue && request.IsActive.Value != existing.IsActive) changedFields.Add("is_active");
            if (changedFields.Count == 0)
            {
                return new ManagedAccountResult(existing.Id, existing.AccountId, existing.FullName, existing.Email,
                    "registrar", existing.Status, existing.IsActive, "Registrar", true);
            }

            if (emailChanged)
            {
                await using var migrateChat = new NpgsqlCommand(@"
                    UPDATE chat_messages SET sender_email = @newEmail WHERE LOWER(sender_email) = LOWER(@oldEmail);
                    UPDATE chat_messages SET receiver_email = @newEmail WHERE LOWER(receiver_email) = LOWER(@oldEmail);
                    DELETE FROM online_status WHERE LOWER(email) = LOWER(@oldEmail);", connection, transaction);
                migrateChat.Parameters.AddWithValue("newEmail", newEmail);
                migrateChat.Parameters.AddWithValue("oldEmail", existing.Email);
                await migrateChat.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var command = new NpgsqlCommand(@"
                UPDATE users
                SET email = @email,
                    password_hash = CASE WHEN @password IS NULL THEN password_hash ELSE crypt(@password, gen_salt('bf')) END,
                    is_active = COALESCE(@isActive, is_active),
                    status = CASE WHEN COALESCE(@isActive, is_active) THEN 'APPROVED' ELSE 'DEACTIVATED' END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = @userId AND LOWER(role) = 'registrar';", connection, transaction))
            {
                command.Parameters.AddWithValue("email", newEmail);
                command.Parameters.AddWithValue("password", (object?)request.Password ?? DBNull.Value);
                command.Parameters.AddWithValue("isActive", (object?)request.IsActive ?? DBNull.Value);
                command.Parameters.AddWithValue("userId", userId);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await _auditLog.LogAsync(actorEmail, "system_admin", "REGISTRAR_ACCOUNT_UPDATED", "user", userId.ToString(),
                new { email = existing.Email, isActive = existing.IsActive },
                new { email = newEmail, isActive = request.IsActive ?? existing.IsActive, changedFields },
                "System Administrator updated Registrar account access.", ipAddress, connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            var ledgerInvoker = emailChanged ? newEmail : existing.Email;
            var ledgerRecorded = await TryRecordRegistrarAuditAsync(
                "REGISTRAR_ACCOUNT_UPDATED", ledgerInvoker, existing.AccountId, actorEmail, changedFields,
                "System Administrator updated Registrar account access.", cancellationToken);
            var active = request.IsActive ?? existing.IsActive;

            var identityWarnings = new List<string>();
            if (emailChanged && !await TryRevokeFabricIdentityAsync(existing.Email, cancellationToken))
            {
                identityWarnings.Add("The previous Registrar blockchain identity could not be revoked automatically.");
            }
            if (!active && (existing.IsActive || emailChanged) &&
                !await TryRemoveFabricWalletAsync(newEmail, cancellationToken))
            {
                identityWarnings.Add("The Registrar was deactivated, but its server-side blockchain wallet could not be removed automatically.");
            }

            var warnings = new List<string>();
            if (!ledgerRecorded) warnings.Add("The immutable audit event could not be recorded.");
            warnings.AddRange(identityWarnings);
            return new ManagedAccountResult(existing.Id, existing.AccountId, existing.FullName, newEmail, "registrar",
                active ? "APPROVED" : "DEACTIVATED", active, "Registrar", ledgerRecorded,
                warnings.Count == 0 ? null : string.Join(" ", warnings));
        }

        public async Task<ManagedAccountResult> DeleteRegistrarAsync(
            int userId,
            string actorEmail,
            string? ipAddress,
            CancellationToken cancellationToken)
        {
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await AcquireRegistrarCapacityLockAsync(connection, transaction, cancellationToken);
            var existing = await GetRegistrarForUpdateAsync(connection, transaction, userId, cancellationToken);

            await using (var command = new NpgsqlCommand(@"
                UPDATE users
                SET role = 'deleted_registrar',
                    status = 'DELETED',
                    is_active = FALSE,
                    password_hash = crypt(gen_random_uuid()::text, gen_salt('bf')),
                    password_reset_token = NULL,
                    password_reset_expires = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = @userId AND LOWER(role) = 'registrar';
                UPDATE adminprofiles
                SET admin_level = 'deleted_registrar'
                WHERE user_id = @userId;", connection, transaction))
            {
                command.Parameters.AddWithValue("userId", userId);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await _auditLog.LogAsync(actorEmail, "system_admin", "REGISTRAR_ACCOUNT_DELETED", "user", userId.ToString(),
                new { existing.AccountId, existing.Email, role = "registrar", existing.Status, existing.IsActive },
                new { existing.AccountId, existing.Email, role = "deleted_registrar", status = "DELETED", isActive = false },
                "System Administrator deleted a Registrar account and released one Registrar slot.",
                ipAddress, connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            var ledgerRecorded = await TryRecordRegistrarAuditAsync(
                "REGISTRAR_ACCOUNT_DELETED", existing.Email, existing.AccountId, actorEmail,
                new[] { "role", "status", "is_active", "password_hash" },
                "System Administrator deleted a Registrar account and released one Registrar slot.", cancellationToken);
            var warnings = new List<string>();
            if (!ledgerRecorded) warnings.Add("The immutable audit event could not be recorded.");
            if (!await TryRevokeFabricIdentityAsync(existing.Email, cancellationToken))
                warnings.Add("The Registrar blockchain identity could not be revoked automatically.");
            if (!await TryRemoveFabricWalletAsync(existing.Email, cancellationToken))
                warnings.Add("The Registrar blockchain wallet could not be removed automatically.");

            return new ManagedAccountResult(existing.Id, existing.AccountId, existing.FullName, existing.Email,
                "deleted_registrar", "DELETED", false, "Registrar", ledgerRecorded,
                warnings.Count == 0 ? null : string.Join(" ", warnings));
        }

        public async Task<ManagedAccountResult> ResetPasswordAsync(
            int userId,
            string newPassword,
            string actorEmail,
            string actorRole,
            string? ipAddress,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8 || newPassword.Length > 128)
            {
                throw new ArgumentException("The new password must be between 8 and 128 characters.");
            }

            var normalizedActorRole = NormalizeAccountRole(actorRole);
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

            (int Id, string AccountId, string FullName, string Email, string Role, string Status, bool IsActive, string? Department) target;
            await using (var lookup = new NpgsqlCommand(@"
                SELECT u.id, COALESCE(u.username, u.id::text),
                       COALESCE(sp.full_name, fp.full_name, ap.full_name, u.email),
                       u.email, u.role, u.status, u.is_active,
                       COALESCE(sp.department, fp.department, ap.department)
                FROM users u
                LEFT JOIN studentprofiles sp ON sp.user_id = u.id
                LEFT JOIN facultyprofiles fp ON fp.user_id = u.id
                LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                WHERE u.id = @userId
                FOR UPDATE OF u;", connection, transaction))
            {
                lookup.Parameters.AddWithValue("userId", userId);
                await using var reader = await lookup.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken))
                {
                    throw new KeyNotFoundException("Account not found.");
                }

                target = (
                    reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    NormalizeAccountRole(reader.GetString(4)), reader.GetString(5), reader.GetBoolean(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7));
            }

            var isAllowed = normalizedActorRole switch
            {
                "registrar" => target.Role is "student" or "faculty" or "department_admin",
                "system_admin" => target.Role == "registrar",
                _ => false
            };
            if (!isAllowed)
            {
                throw new UnauthorizedAccessException(normalizedActorRole == "registrar"
                    ? "Registrars may reset passwords only for students, faculty, and department administrators."
                    : "System Administrators may reset passwords only for Registrar accounts.");
            }

            await using (var update = new NpgsqlCommand(@"
                UPDATE users
                SET password_hash = crypt(@password, gen_salt('bf')),
                    password_reset_token = NULL,
                    password_reset_expires = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = @userId;", connection, transaction))
            {
                update.Parameters.AddWithValue("password", newPassword);
                update.Parameters.AddWithValue("userId", userId);
                await update.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var resetRequestTable = new NpgsqlCommand("SELECT to_regclass('public.password_reset_requests') IS NOT NULL;", connection, transaction))
            {
                var hasResetRequestTable = Convert.ToBoolean(await resetRequestTable.ExecuteScalarAsync(cancellationToken));
                if (hasResetRequestTable)
                {
                    await using var expireRequests = new NpgsqlCommand(@"
                        UPDATE password_reset_requests
                        SET used_at = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT
                        WHERE user_id = @userId AND used_at IS NULL;", connection, transaction);
                    expireRequests.Parameters.AddWithValue("userId", userId);
                    await expireRequests.ExecuteNonQueryAsync(cancellationToken);
                }
            }

            await _auditLog.LogAsync(
                actorEmail, normalizedActorRole, "ACCOUNT_PASSWORD_RESET", "user", userId.ToString(),
                new { target.Role, target.Email },
                new { target.Role, target.Email, passwordReset = true },
                $"{normalizedActorRole} manually reset the password of a {target.Role} account.",
                ipAddress, connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return new ManagedAccountResult(target.Id, target.AccountId, target.FullName, target.Email, target.Role,
                target.Status, target.IsActive, target.Department, true);
        }

        private async Task RegisterFabricIdentityAsync(string email, string password, string role, CancellationToken cancellationToken)
        {
            var client = _httpClientFactory.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/fabric/register-user")
            {
                Content = JsonContent.Create(new { email, password, role })
            };
            request.Headers.Add("x-api-key", _internalApiKey);
            using var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException("The account could not be registered with the blockchain identity service.");
            }
        }

        private string BuildEnrollmentSecret(string email)
        {
            using var hmac = new HMACSHA256(System.Text.Encoding.UTF8.GetBytes(_internalApiKey));
            return Convert.ToHexString(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(email.ToLowerInvariant())));
        }

        private async Task<bool> TryRevokeFabricIdentityAsync(string email, CancellationToken cancellationToken)
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                using var request = new HttpRequestMessage(HttpMethod.Post, $"{_middlewareBaseUrl}/api/revoke")
                {
                    Content = JsonContent.Create(new { username = email, role = "registrar" })
                };
                request.Headers.Add("x-api-key", _internalApiKey);
                using var response = await client.SendAsync(request, cancellationToken);
                return response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.NotFound;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Previous Fabric identity {Email} could not be revoked.", email);
                return false;
            }
        }

        private async Task<bool> TryRemoveFabricWalletAsync(string email, CancellationToken cancellationToken)
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                using var request = new HttpRequestMessage(
                    HttpMethod.Delete,
                    $"{_middlewareBaseUrl}/api/wallet/{Uri.EscapeDataString(email)}");
                request.Headers.Add("x-api-key", _internalApiKey);
                using var response = await client.SendAsync(request, cancellationToken);
                return response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.NotFound;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Fabric wallet {Email} could not be removed during deactivation.", email);
                return false;
            }
        }

        private async Task<bool> TryRecordRegistrarAuditAsync(
            string eventType,
            string ledgerInvoker,
            string entityId,
            string actorEmail,
            IReadOnlyCollection<string> changedFields,
            string description,
            CancellationToken cancellationToken)
        {
            try
            {
                await _blockchain.RecordAuditEventAsync(new BlockchainAuditEvent
                {
                    EventType = eventType,
                    EntityId = entityId,
                    ActorId = actorEmail,
                    ActorRole = "system_admin",
                    ChangedFields = changedFields,
                    Description = description
                }, ledgerInvoker);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Registrar lifecycle event {EventType} was not recorded on Fabric.", eventType);
                return false;
            }
        }

        private static string NormalizeStaffRole(string role)
        {
            var normalized = role.Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
            return normalized switch
            {
                "faculty" => "faculty",
                "chairperson" or "department_head" or "dept_head" or "department_admin" or "dept_admin" => "department_admin",
                _ => throw new ArgumentException("Role must be Faculty or Chairperson/Department Head.")
            };
        }

        private static string NormalizeAccountRole(string role)
        {
            var normalized = role.Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
            return normalized switch
            {
                "dept_admin" or "deptadmin" or "department" or "admin" or "chairperson" or "department_head" or "dept_head" => "department_admin",
                "systemadmin" => "system_admin",
                _ => normalized
            };
        }

        private static async Task<(int Id, string Code, string Name)> ResolveProgramAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            string code,
            CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT program_id, program_code, program_name
                FROM academic_programs
                WHERE LOWER(program_code) = LOWER(@code) AND is_active = TRUE;", connection, transaction);
            command.Parameters.AddWithValue("code", code.Trim());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new ArgumentException("The selected academic program does not exist or is inactive.");
            }
            return (reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
        }

        private static async Task EnsureUniqueAccountAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            string email,
            string accountId,
            CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT COUNT(*) FROM users
                WHERE LOWER(email) = LOWER(@email) OR LOWER(COALESCE(username, '')) = LOWER(@accountId);", connection, transaction);
            command.Parameters.AddWithValue("email", email);
            command.Parameters.AddWithValue("accountId", accountId);
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0)
            {
                throw new InvalidOperationException("An account with that email or institutional ID already exists.");
            }
        }

        private static async Task EnsureRegistrarCapacityAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            CancellationToken cancellationToken)
        {
            await AcquireRegistrarCapacityLockAsync(connection, transaction, cancellationToken);
            await using var command = new NpgsqlCommand(
                "SELECT COUNT(*) FROM users WHERE LOWER(role) = 'registrar';", connection, transaction);
            var count = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            if (count >= MaximumRegistrarAccounts)
            {
                throw new InvalidOperationException($"Only {MaximumRegistrarAccounts} Registrar accounts are allowed. Delete an existing Registrar before creating another one.");
            }
        }

        private static async Task AcquireRegistrarCapacityLockAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(
                "SELECT pg_advisory_xact_lock(@lockId);", connection, transaction);
            command.Parameters.AddWithValue("lockId", RegistrarCapacityLockId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private static async Task EnsureEmailAvailableAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            string email,
            int exceptUserId,
            CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(
                "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(@email) AND id <> @userId;", connection, transaction);
            command.Parameters.AddWithValue("email", email);
            command.Parameters.AddWithValue("userId", exceptUserId);
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0)
            {
                throw new InvalidOperationException("An account with that email already exists.");
            }
        }

        private static async Task EnsureDepartmentHasNoActiveChairAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            string department,
            string programCode,
            CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT COUNT(*)
                FROM users u
                JOIN adminprofiles ap ON ap.user_id = u.id
                WHERE LOWER(u.role) = 'department_admin' AND u.is_active = TRUE
                  AND (LOWER(ap.department) = LOWER(@department) OR LOWER(ap.department) = LOWER(@programCode));", connection, transaction);
            command.Parameters.AddWithValue("department", department);
            command.Parameters.AddWithValue("programCode", programCode);
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0)
            {
                throw new InvalidOperationException("That academic program already has an active Chairperson/Department Head.");
            }
        }

        private static async Task<(int Id, string AccountId, string FullName, string Email, string Status, bool IsActive)> GetRegistrarForUpdateAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            int userId,
            CancellationToken cancellationToken)
        {
            await using var command = new NpgsqlCommand(@"
                SELECT u.id, COALESCE(u.username, u.id::text), COALESCE(ap.full_name, u.email),
                       u.email, u.status, u.is_active
                FROM users u
                LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                WHERE u.id = @userId AND LOWER(u.role) = 'registrar'
                FOR UPDATE OF u;", connection, transaction);
            command.Parameters.AddWithValue("userId", userId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new KeyNotFoundException("Registrar account not found.");
            }
            return (reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetBoolean(5));
        }
    }
}
