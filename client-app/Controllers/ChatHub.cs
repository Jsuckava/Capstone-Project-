using Microsoft.AspNetCore.SignalR;
using Client_app.Models;
using Client_app.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System;
using System.Collections.Generic;
using System.Linq;
using Npgsql;
using NpgsqlTypes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System.Threading;

namespace Client_app.Controllers
{
    [Authorize]
    public class ChatHub : Hub
    {
        private readonly IChatCache _chatCache;
        private readonly IChatMessageEncryption _encryption;
        private readonly ILogger<ChatHub> _logger;
        private readonly string _connectionString;
        private static readonly TimeSpan DatabaseHistoryDuration = TimeSpan.FromDays(30);
        private static readonly SemaphoreSlim ChatSchemaLock = new(1, 1);
        private static bool _chatSchemaReady;

        public ChatHub(IChatCache chatCache, IChatMessageEncryption encryption, IConfiguration configuration, ILogger<ChatHub> logger)
        {
            _chatCache = chatCache;
            _encryption = encryption;
            _logger = logger;
            _connectionString = configuration.GetConnectionString("PostgresConnection") ?? configuration.GetConnectionString("MasterConnection") ?? throw new InvalidOperationException("PostgreSQL connection string not found.");
        }

        public async Task JoinChat(string role)
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrEmpty(userEmail)) return;

            var resolvedRole = ResolveRole(role);
            var normalizedRole = NormalizeRole(resolvedRole);
            await Groups.AddToGroupAsync(Context.ConnectionId, $"private_{userEmail}");
            await Groups.AddToGroupAsync(Context.ConnectionId, $"role_{normalizedRole}");
            await JoinAcceptedGroupChatsAsync(userEmail);
            
            await UpdateOnlineStatus(userEmail, true, resolvedRole);
            await MarkPendingIncomingMessagesDeliveredAsync(userEmail);
            await PresenceAudience(resolvedRole).SendAsync("OnlineStatusChanged", new { Email = userEmail, IsOnline = true });
            await SendContactsToCallerAsync(userEmail, resolvedRole);

            var onlineUsers = await _chatCache.GetOnlineStatusesAsync();
            foreach (var user in onlineUsers.Where(u =>
                         !string.Equals(u.Email, userEmail, StringComparison.OrdinalIgnoreCase) &&
                         IsAllowedChatTarget(resolvedRole, u.Role)))
            {
                await Clients.Caller.SendAsync("UserJoined", new { user.Email, user.Role, user.FullName });
            }
            
            await PresenceAudience(resolvedRole).SendAsync("UserJoined", new { Email = userEmail, Role = resolvedRole, FullName = userEmail.Split('@')[0] });
            await PresenceAudience(resolvedRole).SendAsync("RequestRollCall", userEmail);
        }

        public async Task AnnouncePresence(string targetEmail)
        {
            var myEmail = Context.User?.Identity?.Name;
            var myRole = Context.User?.FindFirst("dbRole")?.Value ?? Context.User?.FindFirst(ClaimTypes.Role)?.Value ?? "student";
            if (string.IsNullOrEmpty(myEmail)) return;

            await EnsureCanSendAsync(targetEmail);
            await Clients.Group($"private_{targetEmail}").SendAsync("UserJoined", new { Email = myEmail, Role = myRole, FullName = myEmail.Split('@')[0] });
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            var userEmail = Context.User?.Identity?.Name;
            if (!string.IsNullOrEmpty(userEmail))
            {
                await _chatCache.UpdateOnlineStatusAsync(userEmail, false, connectionId: Context.ConnectionId);
                var stillOnline = (await _chatCache.GetOnlineStatusesAsync())
                    .Any(u => string.Equals(u.Email, userEmail, StringComparison.OrdinalIgnoreCase));

                if (!stillOnline)
                {
                    var role = ResolveRole();
                    await PresenceAudience(role).SendAsync("OnlineStatusChanged", new { Email = userEmail, IsOnline = false });
                    await PresenceAudience(role).SendAsync("UserLeft", new { Email = userEmail });
                }
            }
            await base.OnDisconnectedAsync(exception);
        }

        public async Task GetChatContacts()
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrEmpty(userEmail)) return;

            await SendContactsToCallerAsync(userEmail, ResolveRole());
        }

        public async Task<IReadOnlyCollection<ChatConversationState>> GetConversationStates()
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(userEmail)) return Array.Empty<ChatConversationState>();

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureChatSchemaAsync(conn);

            using var cmd = new NpgsqlCommand(@"
                SELECT other_user_email, is_archived, deleted_at, updated_at
                FROM chat_conversation_states
                WHERE LOWER(user_email) = LOWER(@userEmail)
                ORDER BY updated_at DESC;", conn);
            cmd.Parameters.AddWithValue("userEmail", userEmail);

            var states = new List<ChatConversationState>();
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                states.Add(new ChatConversationState
                {
                    OtherUserEmail = reader.GetString(0),
                    IsArchived = reader.GetBoolean(1),
                    DeletedAt = reader.IsDBNull(2) ? null : reader.GetDateTime(2),
                    UpdatedAt = reader.GetDateTime(3)
                });
            }
            return states;
        }

        public Task<ChatConversationState> SetConversationArchived(string otherUserEmail, bool isArchived) =>
            SaveConversationStateAsync(otherUserEmail, isArchived, false);

        public async Task<ChatConversationState> DeleteConversation(string otherUserEmail)
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(userEmail) || string.IsNullOrWhiteSpace(otherUserEmail))
            {
                throw new HubException("A conversation must be selected.");
            }

            var state = await SaveConversationStateAsync(otherUserEmail, false, true);
            await _chatCache.DeleteHistoryAsync(userEmail, otherUserEmail);

            await Clients.Group($"private_{userEmail}").SendAsync("ConversationDeleted", new
            {
                OtherUserEmail = otherUserEmail
            });
            await Clients.Group($"private_{otherUserEmail}").SendAsync("ConversationDeleted", new
            {
                OtherUserEmail = userEmail
            });
            return state;
        }

        public Task<ChatConversationState> RestoreConversation(string otherUserEmail) =>
            SaveConversationStateAsync(otherUserEmail, false, false);

        public async Task<object> GetGroupChatData()
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(userEmail)) throw new HubException("Authentication is required.");

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureChatSchemaAsync(conn);

            var groups = await GetAcceptedGroupsAsync(conn, userEmail);
            var invitations = new List<ChatGroupInvitation>();
            using (var invitationCmd = new NpgsqlCommand(@"
                SELECT g.id, g.name, gm.invited_by, gm.invited_at,
                       (SELECT COUNT(*) FROM chat_group_members members WHERE members.group_id = g.id AND members.status = 'accepted') AS member_count
                FROM chat_group_members gm
                JOIN chat_groups g ON g.id = gm.group_id AND g.is_active = TRUE
                WHERE LOWER(gm.user_email) = LOWER(@userEmail)
                  AND gm.status = 'pending'
                ORDER BY gm.invited_at DESC;", conn))
            {
                invitationCmd.Parameters.AddWithValue("userEmail", userEmail);
                using var reader = await invitationCmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    invitations.Add(new ChatGroupInvitation
                    {
                        GroupId = reader.GetInt64(0),
                        GroupName = reader.GetString(1),
                        InvitedBy = reader.GetString(2),
                        InvitedAt = reader.GetDateTime(3),
                        MemberCount = Convert.ToInt32(reader.GetInt64(4))
                    });
                }
            }

            var eligibleUsers = new List<ChatUserStatus>();
            if (CanCreateGroupChat(ResolveRole()))
            {
                using var contactsCmd = new NpgsqlCommand(@"
                    SELECT u.email, u.role,
                           COALESCE(sp.full_name, fp.full_name, ap.full_name, split_part(u.email, '@', 1)) AS full_name
                    FROM users u
                    LEFT JOIN studentprofiles sp ON sp.user_id = u.id
                    LEFT JOIN facultyprofiles fp ON fp.user_id = u.id
                    LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                    WHERE LOWER(u.email) <> LOWER(@userEmail)
                      AND LOWER(u.status) = 'approved'
                      AND u.is_active = TRUE
                    ORDER BY full_name, u.email;", conn);
                contactsCmd.Parameters.AddWithValue("userEmail", userEmail);
                using var reader = await contactsCmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    eligibleUsers.Add(new ChatUserStatus
                    {
                        Email = reader.GetString(0),
                        Role = reader.GetString(1),
                        FullName = reader.IsDBNull(2) ? reader.GetString(0) : reader.GetString(2)
                    });
                }
            }

            return new { Groups = groups, Invitations = invitations, EligibleUsers = eligibleUsers, MaximumGroups = 10, MaximumMembers = 50 };
        }

        public async Task<ChatGroupSummary> CreateGroupChat(string name, string[] invitedUserEmails)
        {
            var creatorEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(creatorEmail)) throw new HubException("Authentication is required.");
            if (!CanCreateGroupChat(ResolveRole())) throw new HubException("Only Registrar, Department Head, and Faculty accounts can create group chats.");

            var normalizedName = (name ?? string.Empty).Trim();
            if (normalizedName.Length < 2 || normalizedName.Length > 100) throw new HubException("Group name must be between 2 and 100 characters.");

            var invitees = (invitedUserEmails ?? Array.Empty<string>())
                .Where(email => !string.IsNullOrWhiteSpace(email) && !string.Equals(email, creatorEmail, StringComparison.OrdinalIgnoreCase))
                .Select(email => email.Trim().ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (invitees.Length > 49) throw new HubException("A group chat can contain at most 50 people including its creator.");

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureChatSchemaAsync(conn);
            await using var transaction = await conn.BeginTransactionAsync();

            var activeGroupCount = await GetAcceptedGroupCountAsync(conn, transaction, creatorEmail);
            if (activeGroupCount >= 10) throw new HubException("You can create or accept no more than 10 active group chats.");

            if (invitees.Length > 0)
            {
                using var validateCmd = new NpgsqlCommand(@"
                    SELECT COUNT(*)
                    FROM users
                    WHERE LOWER(email) = ANY(@emails)
                      AND LOWER(status) = 'approved'
                      AND is_active = TRUE;", conn, transaction);
                validateCmd.Parameters.AddWithValue("emails", NpgsqlDbType.Array | NpgsqlDbType.Text, invitees);
                var validCount = Convert.ToInt32(await validateCmd.ExecuteScalarAsync());
                if (validCount != invitees.Length) throw new HubException("One or more invited users are unavailable.");
            }

            long groupId;
            var createdAt = DateTime.UtcNow;
            using (var createCmd = new NpgsqlCommand(@"
                INSERT INTO chat_groups (name, created_by, created_at, is_active)
                VALUES (@name, @createdBy, @createdAt, TRUE)
                RETURNING id;", conn, transaction))
            {
                createCmd.Parameters.AddWithValue("name", normalizedName);
                createCmd.Parameters.AddWithValue("createdBy", creatorEmail.Trim().ToLowerInvariant());
                createCmd.Parameters.AddWithValue("createdAt", createdAt);
                groupId = Convert.ToInt64(await createCmd.ExecuteScalarAsync());
            }

            using (var ownerCmd = new NpgsqlCommand(@"
                INSERT INTO chat_group_members (group_id, user_email, status, invited_by, invited_at, responded_at, joined_at)
                VALUES (@groupId, @userEmail, 'accepted', @userEmail, @createdAt, @createdAt, @createdAt);", conn, transaction))
            {
                ownerCmd.Parameters.AddWithValue("groupId", groupId);
                ownerCmd.Parameters.AddWithValue("userEmail", creatorEmail.Trim().ToLowerInvariant());
                ownerCmd.Parameters.AddWithValue("createdAt", createdAt);
                await ownerCmd.ExecuteNonQueryAsync();
            }

            foreach (var invitee in invitees)
            {
                using var inviteCmd = new NpgsqlCommand(@"
                    INSERT INTO chat_group_members (group_id, user_email, status, invited_by, invited_at)
                    VALUES (@groupId, @userEmail, 'pending', @createdBy, @createdAt);", conn, transaction);
                inviteCmd.Parameters.AddWithValue("groupId", groupId);
                inviteCmd.Parameters.AddWithValue("userEmail", invitee);
                inviteCmd.Parameters.AddWithValue("createdBy", creatorEmail.Trim().ToLowerInvariant());
                inviteCmd.Parameters.AddWithValue("createdAt", createdAt);
                await inviteCmd.ExecuteNonQueryAsync();
            }

            await transaction.CommitAsync();
            await Groups.AddToGroupAsync(Context.ConnectionId, $"chat_group_{groupId}");

            var invitation = new ChatGroupInvitation
            {
                GroupId = groupId,
                GroupName = normalizedName,
                InvitedBy = creatorEmail,
                InvitedAt = createdAt,
                MemberCount = 1
            };
            foreach (var invitee in invitees)
            {
                await Clients.Group($"private_{invitee}").SendAsync("GroupInvitationReceived", invitation);
            }

            return new ChatGroupSummary
            {
                Id = groupId,
                Name = normalizedName,
                CreatedBy = creatorEmail,
                CreatedAt = createdAt,
                MemberCount = 1,
                IsOwner = true
            };
        }

        public async Task RespondToGroupInvitation(long groupId, bool accept)
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(userEmail)) throw new HubException("Authentication is required.");

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureChatSchemaAsync(conn);
            await using var transaction = await conn.BeginTransactionAsync();

            using (var lockCmd = new NpgsqlCommand(@"
                SELECT 1
                FROM chat_group_members gm
                JOIN chat_groups g ON g.id = gm.group_id AND g.is_active = TRUE
                WHERE gm.group_id = @groupId
                  AND LOWER(gm.user_email) = LOWER(@userEmail)
                  AND gm.status = 'pending'
                FOR UPDATE;", conn, transaction))
            {
                lockCmd.Parameters.AddWithValue("groupId", groupId);
                lockCmd.Parameters.AddWithValue("userEmail", userEmail);
                if (await lockCmd.ExecuteScalarAsync() is null) throw new HubException("This group invitation is no longer available.");
            }

            if (accept && await GetAcceptedGroupCountAsync(conn, transaction, userEmail) >= 10)
            {
                throw new HubException("You can create or accept no more than 10 active group chats.");
            }

            var now = DateTime.UtcNow;
            using (var updateCmd = new NpgsqlCommand(@"
                UPDATE chat_group_members
                SET status = @status,
                    responded_at = @respondedAt,
                    joined_at = CASE WHEN @accept THEN @respondedAt ELSE NULL END
                WHERE group_id = @groupId AND LOWER(user_email) = LOWER(@userEmail);", conn, transaction))
            {
                updateCmd.Parameters.AddWithValue("status", accept ? "accepted" : "declined");
                updateCmd.Parameters.AddWithValue("respondedAt", now);
                updateCmd.Parameters.AddWithValue("accept", accept);
                updateCmd.Parameters.AddWithValue("groupId", groupId);
                updateCmd.Parameters.AddWithValue("userEmail", userEmail);
                await updateCmd.ExecuteNonQueryAsync();
            }
            await transaction.CommitAsync();

            if (accept) await Groups.AddToGroupAsync(Context.ConnectionId, $"chat_group_{groupId}");
            await Clients.Group($"chat_group_{groupId}").SendAsync("GroupMembershipChanged", new { GroupId = groupId });
        }

        public async Task GetGroupChatHistory(long groupId)
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(userEmail)) return;

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureAcceptedGroupMemberAsync(conn, groupId, userEmail);

            var history = new List<ChatGroupMessage>();
            using var cmd = new NpgsqlCommand(@"
                SELECT gm.id, gm.group_id, gm.sender_email,
                       COALESCE(sp.full_name, fp.full_name, ap.full_name, split_part(gm.sender_email, '@', 1)) AS sender_name,
                       gm.message, gm.sent_at
                FROM chat_group_messages gm
                LEFT JOIN users u ON LOWER(u.email) = LOWER(gm.sender_email)
                LEFT JOIN studentprofiles sp ON sp.user_id = u.id
                LEFT JOIN facultyprofiles fp ON fp.user_id = u.id
                LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                WHERE gm.group_id = @groupId
                  AND gm.sent_at >= @cutoff
                ORDER BY gm.sent_at ASC;", conn);
            cmd.Parameters.AddWithValue("groupId", groupId);
            cmd.Parameters.AddWithValue("cutoff", DateTime.UtcNow.Subtract(DatabaseHistoryDuration));
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                string message;
                try { message = _encryption.Decrypt(reader.GetString(4)); }
                catch { continue; }
                history.Add(new ChatGroupMessage
                {
                    Id = reader.GetInt64(0),
                    GroupId = reader.GetInt64(1),
                    SenderEmail = reader.GetString(2),
                    SenderName = reader.IsDBNull(3) ? reader.GetString(2) : reader.GetString(3),
                    Message = message,
                    SentAt = reader.GetDateTime(5)
                });
            }
            await Clients.Caller.SendAsync("GroupChatHistory", new { GroupId = groupId, Messages = history });
        }

        public async Task SendGroupMessage(long groupId, string message)
        {
            var senderEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(senderEmail) || string.IsNullOrWhiteSpace(message)) return;
            var normalizedMessage = message.Trim();
            if (normalizedMessage.Length > 4000) throw new HubException("Group messages cannot exceed 4,000 characters.");

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureAcceptedGroupMemberAsync(conn, groupId, senderEmail);

            var sentAt = DateTime.UtcNow;
            long messageId;
            using (var cmd = new NpgsqlCommand(@"
                INSERT INTO chat_group_messages (group_id, sender_email, message, sent_at)
                VALUES (@groupId, @senderEmail, @message, @sentAt)
                RETURNING id;", conn))
            {
                cmd.Parameters.AddWithValue("groupId", groupId);
                cmd.Parameters.AddWithValue("senderEmail", senderEmail);
                cmd.Parameters.AddWithValue("message", _encryption.Encrypt(normalizedMessage));
                cmd.Parameters.AddWithValue("sentAt", sentAt);
                messageId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            }

            await Clients.Group($"chat_group_{groupId}").SendAsync("ReceiveGroupMessage", new ChatGroupMessage
            {
                Id = messageId,
                GroupId = groupId,
                SenderEmail = senderEmail,
                SenderName = senderEmail.Split('@')[0],
                Message = normalizedMessage,
                SentAt = sentAt
            });
        }

        public async Task SendMessage(string receiverEmail, string message)
        {
            var senderEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrEmpty(senderEmail) || string.IsNullOrEmpty(receiverEmail)) return;
            if (string.IsNullOrWhiteSpace(message)) return;

            await EnsureCanSendAsync(receiverEmail);

            var chatMessage = new ChatMessage
            {
                SenderEmail = senderEmail,
                ReceiverEmail = receiverEmail,
                Message = message.Trim(),
                Timestamp = DateTime.UtcNow,
                SentAt = DateTime.UtcNow,
                IsRead = false
            };

            await SaveAndBroadcastAsync(chatMessage);
        }

        public async Task SendFile(
            string receiverEmail,
            string fileName,
            string mimeType,
            long sizeBytes,
            string base64Data,
            string message)
        {
            var senderEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrEmpty(senderEmail) || string.IsNullOrEmpty(receiverEmail)) return;
            if (string.IsNullOrWhiteSpace(fileName)) return;
            await EnsureCanSendAsync(receiverEmail);

            byte[] attachmentBytes;
            try
            {
                attachmentBytes = Convert.FromBase64String(base64Data ?? string.Empty);
            }
            catch (FormatException)
            {
                throw new HubException("Invalid file data.");
            }

            const int maxBytes = 5 * 1024 * 1024;
            if (attachmentBytes.Length == 0 || attachmentBytes.Length > maxBytes || sizeBytes > maxBytes)
            {
                throw new HubException("File too large or empty. Maximum size is 5MB.");
            }

            var now = DateTime.UtcNow;
            var chatMessage = new ChatMessage
            {
                SenderEmail = senderEmail,
                ReceiverEmail = receiverEmail,
                Message = message?.Trim() ?? string.Empty,
                Timestamp = now,
                SentAt = now,
                AttachmentName = fileName,
                AttachmentMime = string.IsNullOrWhiteSpace(mimeType) ? "application/octet-stream" : mimeType,
                AttachmentSizeBytes = sizeBytes,
                AttachmentData = attachmentBytes,
                AttachmentDataBase64 = Convert.ToBase64String(attachmentBytes),
                IsRead = false
            };

            await SaveAndBroadcastAsync(chatMessage);
        }

        public async Task GetChatHistory(string otherUserEmail)
        {
            var senderEmail = Context.User?.Identity?.Name ?? string.Empty;
            
            if (!string.IsNullOrEmpty(senderEmail) && !string.IsNullOrEmpty(otherUserEmail))
            {
                await EnsureCanSendAsync(otherUserEmail);
                var history = await GetMergedHistoryAsync(senderEmail, otherUserEmail);
                await Clients.Caller.SendAsync("ChatHistory", history);
            }
        }

        public async Task MarkConversationSeen(string otherUserEmail)
        {
            var viewerEmail = Context.User?.Identity?.Name ?? string.Empty;

            if (string.IsNullOrEmpty(viewerEmail) || string.IsNullOrEmpty(otherUserEmail)) return;

            await EnsureCanSendAsync(otherUserEmail);

            var history = await GetMergedHistoryAsync(viewerEmail, otherUserEmail);
            await MarkConversationSeenAsync(viewerEmail, otherUserEmail, history);
        }

        public async Task SetTyping(string receiverEmail, bool isTyping)
        {
            var senderEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrEmpty(senderEmail) || string.IsNullOrEmpty(receiverEmail)) return;

            await EnsureCanSendAsync(receiverEmail);

            await Clients.Group($"private_{receiverEmail}").SendAsync("UserTyping", new
            {
                Sender = senderEmail,
                Receiver = receiverEmail,
                IsTyping = isTyping
            });
        }

        private async Task SaveAndBroadcastAsync(ChatMessage chatMessage)
        {
            var userRole = ResolveRole();
            var displayName = chatMessage.SenderEmail.Split('@')[0].Replace(".", " ");
            chatMessage.SentAt = chatMessage.SentAt == default ? DateTime.UtcNow : chatMessage.SentAt;
            chatMessage.Timestamp = chatMessage.Timestamp == default ? chatMessage.SentAt : chatMessage.Timestamp;

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);

                using var cmd = new NpgsqlCommand(@"
                    INSERT INTO chat_messages (
                        sender_email,
                        receiver_email,
                        message,
                        timestamp,
                        sent_at,
                        is_read,
                        attachment_name,
                        attachment_mime,
                        attachment_size_bytes,
                        attachment_data
                    )
                    VALUES (
                        @sender,
                        @receiver,
                        @msg,
                        @ts,
                        @sentAt,
                        false,
                        @attachmentName,
                        @attachmentMime,
                        @attachmentSizeBytes,
                        @attachmentData
                    )
                    RETURNING id, delivered_at, seen_at;", conn);
                cmd.Parameters.AddWithValue("sender", chatMessage.SenderEmail);
                cmd.Parameters.AddWithValue("receiver", chatMessage.ReceiverEmail);
                cmd.Parameters.AddWithValue("msg", _encryption.Encrypt(chatMessage.Message));
                cmd.Parameters.AddWithValue("ts", chatMessage.Timestamp);
                cmd.Parameters.AddWithValue("sentAt", chatMessage.SentAt);
                cmd.Parameters.Add("attachmentName", NpgsqlDbType.Varchar).Value = (object?)chatMessage.AttachmentName ?? DBNull.Value;
                cmd.Parameters.Add("attachmentMime", NpgsqlDbType.Varchar).Value = (object?)chatMessage.AttachmentMime ?? DBNull.Value;
                cmd.Parameters.Add("attachmentSizeBytes", NpgsqlDbType.Bigint).Value = (object?)chatMessage.AttachmentSizeBytes ?? DBNull.Value;
                cmd.Parameters.Add("attachmentData", NpgsqlDbType.Bytea).Value = (object?)chatMessage.AttachmentData ?? DBNull.Value;

                using var reader = await cmd.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    chatMessage.Id = reader.GetInt32(0);
                    chatMessage.DeliveredAt = reader.IsDBNull(1) ? null : reader.GetDateTime(1);
                    chatMessage.SeenAt = reader.IsDBNull(2) ? null : reader.GetDateTime(2);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Chat message was not persisted to the database. Realtime delivery will continue from cache.");
            }

            await MarkDeliveredIfReceiverOnlineAsync(chatMessage);
            await ReactivateConversationForParticipantsAsync(chatMessage.SenderEmail, chatMessage.ReceiverEmail);
            await _chatCache.SaveMessageAsync(chatMessage);

            var payload = new 
            { 
                MessageId = chatMessage.Id,
                Sender = chatMessage.SenderEmail, 
                Receiver = chatMessage.ReceiverEmail,
                SenderName = displayName,
                Role = userRole,
                Message = chatMessage.Message, 
                Text = chatMessage.Message,
                Timestamp = chatMessage.SentAt,
                SentAt = chatMessage.SentAt,
                DeliveredAt = chatMessage.DeliveredAt,
                SeenAt = chatMessage.SeenAt,
                chatMessage.AttachmentName,
                chatMessage.AttachmentMime,
                chatMessage.AttachmentSizeBytes,
                AttachmentDataBase64 = chatMessage.AttachmentDataBase64
            };
            await Clients.Groups(new List<string> { $"private_{chatMessage.ReceiverEmail}", $"private_{chatMessage.SenderEmail}" }).SendAsync("ReceiveMessage", payload);

            if (chatMessage.Id > 0 && chatMessage.DeliveredAt is not null)
            {
                await Clients.Group($"private_{chatMessage.SenderEmail}").SendAsync("MessageDelivered", new
                {
                    MessageId = chatMessage.Id,
                    DeliveredAt = chatMessage.DeliveredAt
                });
            }
        }

        private async Task MarkDeliveredIfReceiverOnlineAsync(ChatMessage chatMessage)
        {
            var onlineUsers = await _chatCache.GetOnlineStatusesAsync();
            var receiverOnline = onlineUsers.Any(u =>
                string.Equals(u.Email, chatMessage.ReceiverEmail, StringComparison.OrdinalIgnoreCase));

            if (!receiverOnline) return;

            chatMessage.DeliveredAt = DateTime.UtcNow;

            if (chatMessage.Id <= 0) return;

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);

                using var cmd = new NpgsqlCommand(@"
                    UPDATE chat_messages
                    SET delivered_at = COALESCE(delivered_at, @deliveredAt)
                    WHERE id = @id;", conn);
                cmd.Parameters.AddWithValue("deliveredAt", chatMessage.DeliveredAt);
                cmd.Parameters.AddWithValue("id", chatMessage.Id);
                await cmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to mark chat message as delivered.");
            }
        }

        private async Task MarkPendingIncomingMessagesDeliveredAsync(string receiverEmail)
        {
            if (string.IsNullOrWhiteSpace(receiverEmail)) return;

            var deliveredAt = DateTime.UtcNow;
            var deliveredMessages = new List<(int MessageId, string SenderEmail)>();

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);

                using var cmd = new NpgsqlCommand(@"
                    UPDATE chat_messages
                    SET delivered_at = COALESCE(delivered_at, @deliveredAt)
                    WHERE LOWER(receiver_email) = LOWER(@receiverEmail)
                      AND delivered_at IS NULL
                      AND COALESCE(sent_at, timestamp) >= @cutoff
                    RETURNING id, sender_email;", conn);
                cmd.Parameters.AddWithValue("deliveredAt", deliveredAt);
                cmd.Parameters.AddWithValue("receiverEmail", receiverEmail);
                cmd.Parameters.AddWithValue("cutoff", DateTime.UtcNow.Subtract(DatabaseHistoryDuration));

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    deliveredMessages.Add((reader.GetInt32(0), reader.GetString(1)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to mark pending incoming chat messages as delivered for {ReceiverEmail}.", receiverEmail);
                return;
            }

            foreach (var deliveredMessage in deliveredMessages)
            {
                await Clients.Group($"private_{deliveredMessage.SenderEmail}").SendAsync("MessageDelivered", new
                {
                    MessageId = deliveredMessage.MessageId,
                    DeliveredAt = deliveredAt
                });
            }
        }

        private async Task<List<ChatMessage>> GetMergedHistoryAsync(string userEmail, string otherUserEmail)
        {
            var byId = new Dictionary<int, ChatMessage>();
            var cacheHistory = await _chatCache.GetHistoryAsync(userEmail, otherUserEmail);

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);

                using var cmd = new NpgsqlCommand(@"
                    SELECT
                        id,
                        sender_email,
                        receiver_email,
                        message,
                        COALESCE(sent_at, timestamp) AS sent_at,
                        delivered_at,
                        seen_at,
                        is_read,
                        attachment_name,
                        attachment_mime,
                        attachment_size_bytes,
                        attachment_data
                    FROM chat_messages
                    WHERE (
                        (LOWER(sender_email) = LOWER(@userEmail) AND LOWER(receiver_email) = LOWER(@otherUserEmail))
                        OR
                        (LOWER(sender_email) = LOWER(@otherUserEmail) AND LOWER(receiver_email) = LOWER(@userEmail))
                    )
                    AND COALESCE(sent_at, timestamp) >= @cutoff
                    ORDER BY COALESCE(sent_at, timestamp) ASC;", conn);
                cmd.Parameters.AddWithValue("userEmail", userEmail);
                cmd.Parameters.AddWithValue("otherUserEmail", otherUserEmail);
                cmd.Parameters.AddWithValue("cutoff", DateTime.UtcNow.Subtract(DatabaseHistoryDuration));

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var id = reader.GetInt32(0);
                    var message = new ChatMessage
                    {
                        Id = id,
                        SenderEmail = reader.GetString(1),
                        ReceiverEmail = reader.GetString(2),
                        SentAt = reader.GetDateTime(4),
                        Timestamp = reader.GetDateTime(4),
                        DeliveredAt = reader.IsDBNull(5) ? null : reader.GetDateTime(5),
                        SeenAt = reader.IsDBNull(6) ? null : reader.GetDateTime(6),
                        IsRead = !reader.IsDBNull(7) && reader.GetBoolean(7),
                        AttachmentName = reader.IsDBNull(8) ? null : reader.GetString(8),
                        AttachmentMime = reader.IsDBNull(9) ? null : reader.GetString(9),
                        AttachmentSizeBytes = reader.IsDBNull(10) ? null : reader.GetInt64(10),
                        AttachmentDataBase64 = reader.IsDBNull(11) ? null : Convert.ToBase64String((byte[])reader[11])
                    };

                    try
                    {
                        message.Message = _encryption.Decrypt(reader.GetString(3));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Skipping chat message {MessageId} because it could not be decrypted.", id);
                        continue;
                    }

                    byId[id] = message;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load chat history from the database. Returning cache history only.");
            }

            foreach (var message in cacheHistory.Where(m => m.Id <= 0))
            {
                byId[message.GetHashCode()] = message;
            }

            return byId.Values
                .OrderBy(m => m.SentAt == default ? m.Timestamp : m.SentAt)
                .ToList();
        }

        private async Task MarkConversationSeenAsync(string viewerEmail, string otherUserEmail, List<ChatMessage> history)
        {
            var seenAt = DateTime.UtcNow;
            var messageIds = history
                .Where(m =>
                    m.Id > 0 &&
                    string.Equals(m.SenderEmail, otherUserEmail, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(m.ReceiverEmail, viewerEmail, StringComparison.OrdinalIgnoreCase) &&
                    m.SeenAt is null)
                .Select(m => m.Id)
                .ToArray();

            if (messageIds.Length == 0) return;

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);

                using var cmd = new NpgsqlCommand(@"
                    UPDATE chat_messages
                    SET seen_at = COALESCE(seen_at, @seenAt),
                        delivered_at = COALESCE(delivered_at, @seenAt),
                        is_read = true
                    WHERE id = ANY(@ids);", conn);
                cmd.Parameters.AddWithValue("seenAt", seenAt);
                cmd.Parameters.AddWithValue("ids", messageIds);
                await cmd.ExecuteNonQueryAsync();

                foreach (var message in history.Where(m => messageIds.Contains(m.Id)))
                {
                    message.SeenAt = seenAt;
                    message.DeliveredAt ??= seenAt;
                    message.IsRead = true;
                    await Clients.Group($"private_{message.SenderEmail}").SendAsync("MessageSeen", new
                    {
                        MessageId = message.Id,
                        SeenAt = message.SeenAt,
                        DeliveredAt = message.DeliveredAt
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to mark chat messages as seen.");
            }
        }

        private static async Task EnsureChatSchemaAsync(NpgsqlConnection conn)
        {
            if (Volatile.Read(ref _chatSchemaReady)) return;
            await ChatSchemaLock.WaitAsync();
            try
            {
                if (Volatile.Read(ref _chatSchemaReady)) return;
            using var cmd = new NpgsqlCommand(@"
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id SERIAL PRIMARY KEY,
                    sender_email VARCHAR(100) NOT NULL,
                    receiver_email VARCHAR(100) NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT false,
                    attachment_name VARCHAR(255),
                    attachment_mime VARCHAR(100),
                    attachment_size_bytes BIGINT,
                    attachment_data BYTEA,
                    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    delivered_at TIMESTAMP WITH TIME ZONE,
                    seen_at TIMESTAMP WITH TIME ZONE
                );
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT false;
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_name VARCHAR(255);
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_mime VARCHAR(100);
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_size_bytes BIGINT;
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_data BYTEA;
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP WITH TIME ZONE;
                ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS seen_at TIMESTAMP WITH TIME ZONE;
                ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS chat_messages_sender_email_fkey;
                ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS chat_messages_receiver_email_fkey;
                UPDATE chat_messages SET sent_at = COALESCE(sent_at, timestamp, CURRENT_TIMESTAMP) WHERE sent_at IS NULL;
                UPDATE chat_messages SET timestamp = COALESCE(timestamp, sent_at, CURRENT_TIMESTAMP) WHERE timestamp IS NULL;
                CREATE INDEX IF NOT EXISTS idx_chat_messages_sender ON chat_messages(sender_email);
                CREATE INDEX IF NOT EXISTS idx_chat_messages_receiver ON chat_messages(receiver_email);
                CREATE INDEX IF NOT EXISTS idx_chat_messages_sent_at ON chat_messages(sent_at);
                CREATE INDEX IF NOT EXISTS idx_chat_messages_pair_sent_at ON chat_messages(LOWER(sender_email), LOWER(receiver_email), sent_at);
                CREATE TABLE IF NOT EXISTS chat_conversation_states (
                    user_email VARCHAR(255) NOT NULL,
                    other_user_email VARCHAR(255) NOT NULL,
                    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
                    deleted_at TIMESTAMP WITH TIME ZONE,
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_email, other_user_email),
                    CONSTRAINT chat_conversation_states_different_users CHECK (LOWER(user_email) <> LOWER(other_user_email))
                );
                CREATE INDEX IF NOT EXISTS idx_chat_conversation_states_user_updated
                    ON chat_conversation_states(LOWER(user_email), updated_at DESC);
                CREATE TABLE IF NOT EXISTS chat_groups (
                    id BIGSERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    created_by VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE
                );
                CREATE TABLE IF NOT EXISTS chat_group_members (
                    group_id BIGINT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
                    user_email VARCHAR(255) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    invited_by VARCHAR(255) NOT NULL,
                    invited_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    responded_at TIMESTAMP WITH TIME ZONE,
                    joined_at TIMESTAMP WITH TIME ZONE,
                    PRIMARY KEY (group_id, user_email),
                    CONSTRAINT chat_group_member_status CHECK (status IN ('pending', 'accepted', 'declined'))
                );
                CREATE TABLE IF NOT EXISTS chat_group_messages (
                    id BIGSERIAL PRIMARY KEY,
                    group_id BIGINT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
                    sender_email VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    sent_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_chat_group_members_user_status
                    ON chat_group_members(LOWER(user_email), status);
                CREATE INDEX IF NOT EXISTS idx_chat_group_messages_group_sent
                    ON chat_group_messages(group_id, sent_at);
                DELETE FROM chat_messages WHERE COALESCE(sent_at, timestamp) < NOW() - INTERVAL '30 days';
                DELETE FROM chat_group_messages WHERE sent_at < NOW() - INTERVAL '30 days';", conn);
            await cmd.ExecuteNonQueryAsync();
                Volatile.Write(ref _chatSchemaReady, true);
            }
            finally
            {
                ChatSchemaLock.Release();
            }
        }

        private async Task<ChatConversationState> SaveConversationStateAsync(
            string otherUserEmail,
            bool isArchived,
            bool isDeleted)
        {
            var userEmail = Context.User?.Identity?.Name;
            if (string.IsNullOrWhiteSpace(userEmail) || string.IsNullOrWhiteSpace(otherUserEmail))
            {
                throw new HubException("A conversation must be selected.");
            }

            await EnsureCanSendAsync(otherUserEmail);
            var normalizedUser = userEmail.Trim().ToLowerInvariant();
            var normalizedOther = otherUserEmail.Trim().ToLowerInvariant();
            var now = DateTime.UtcNow;

            using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await EnsureChatSchemaAsync(conn);
            await using var transaction = await conn.BeginTransactionAsync();

            if (!isArchived && !isDeleted)
            {
                using var deleteCmd = new NpgsqlCommand(@"
                    DELETE FROM chat_conversation_states
                    WHERE LOWER(user_email) = LOWER(@userEmail)
                      AND LOWER(other_user_email) = LOWER(@otherUserEmail);", conn, transaction);
                deleteCmd.Parameters.AddWithValue("userEmail", normalizedUser);
                deleteCmd.Parameters.AddWithValue("otherUserEmail", normalizedOther);
                await deleteCmd.ExecuteNonQueryAsync();
            }
            else
            {
                if (isDeleted)
                {
                    using var purgeCmd = new NpgsqlCommand(@"
                        DELETE FROM chat_messages
                        WHERE
                            (LOWER(sender_email) = LOWER(@userEmail) AND LOWER(receiver_email) = LOWER(@otherUserEmail))
                            OR
                            (LOWER(sender_email) = LOWER(@otherUserEmail) AND LOWER(receiver_email) = LOWER(@userEmail));", conn, transaction);
                    purgeCmd.Parameters.AddWithValue("userEmail", normalizedUser);
                    purgeCmd.Parameters.AddWithValue("otherUserEmail", normalizedOther);
                    await purgeCmd.ExecuteNonQueryAsync();
                }

                using var upsertCmd = new NpgsqlCommand(@"
                    INSERT INTO chat_conversation_states (
                        user_email, other_user_email, is_archived, deleted_at, updated_at
                    ) VALUES (
                        @userEmail, @otherUserEmail, @isArchived,
                        CASE WHEN @isDeleted THEN @updatedAt ELSE NULL END,
                        @updatedAt
                    )
                    ON CONFLICT (user_email, other_user_email) DO UPDATE SET
                        is_archived = EXCLUDED.is_archived,
                        deleted_at = EXCLUDED.deleted_at,
                        updated_at = EXCLUDED.updated_at;", conn, transaction);
                upsertCmd.Parameters.AddWithValue("userEmail", normalizedUser);
                upsertCmd.Parameters.AddWithValue("otherUserEmail", normalizedOther);
                upsertCmd.Parameters.AddWithValue("isArchived", isArchived);
                upsertCmd.Parameters.AddWithValue("isDeleted", isDeleted);
                upsertCmd.Parameters.AddWithValue("updatedAt", now);
                await upsertCmd.ExecuteNonQueryAsync();
            }
            await transaction.CommitAsync();

            var state = new ChatConversationState
            {
                OtherUserEmail = normalizedOther,
                IsArchived = isArchived,
                DeletedAt = isDeleted ? now : null,
                UpdatedAt = now
            };
            await Clients.Group($"private_{userEmail}").SendAsync("ConversationStateChanged", state);
            return state;
        }

        private async Task ReactivateConversationForParticipantsAsync(string senderEmail, string receiverEmail)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);
                using var cmd = new NpgsqlCommand(@"
                    DELETE FROM chat_conversation_states
                    WHERE
                        (LOWER(user_email) = LOWER(@sender) AND LOWER(other_user_email) = LOWER(@receiver))
                        OR
                        (LOWER(user_email) = LOWER(@receiver) AND LOWER(other_user_email) = LOWER(@sender));", conn);
                cmd.Parameters.AddWithValue("sender", senderEmail);
                cmd.Parameters.AddWithValue("receiver", receiverEmail);
                await cmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to reactivate chat conversation state after a message was sent.");
            }
        }

        private async Task SendContactsToCallerAsync(string userEmail, string viewerRole)
        {
            var onlineUsers = await _chatCache.GetOnlineStatusesAsync();
            var onlineByEmail = onlineUsers.ToDictionary(u => u.Email, StringComparer.OrdinalIgnoreCase);
            var contacts = new List<ChatUserStatus>();

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);

                using var cmd = new NpgsqlCommand(@"
                    SELECT
                        u.email,
                        u.role,
                        COALESCE(sp.full_name, fp.full_name, ap.full_name, split_part(u.email, '@', 1)) AS full_name,
                        EXISTS (
                            SELECT 1
                            FROM chat_messages cm
                            WHERE (
                                (LOWER(cm.sender_email) = LOWER(@userEmail) AND LOWER(cm.receiver_email) = LOWER(u.email))
                                OR
                                (LOWER(cm.sender_email) = LOWER(u.email) AND LOWER(cm.receiver_email) = LOWER(@userEmail))
                            )
                            AND COALESCE(cm.sent_at, cm.timestamp) >= NOW() - INTERVAL '30 days'
                        ) AS has_conversation
                    FROM users u
                    LEFT JOIN studentprofiles sp ON sp.user_id = u.id
                    LEFT JOIN facultyprofiles fp ON fp.user_id = u.id
                    LEFT JOIN adminprofiles ap ON ap.user_id = u.id
                    WHERE LOWER(u.email) <> LOWER(@userEmail)
                      AND LOWER(u.status) = 'approved'
                      AND u.is_active = TRUE
                    ORDER BY full_name, u.email;", conn);
                cmd.Parameters.AddWithValue("userEmail", userEmail);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var email = reader.GetString(0);
                    var role = reader.GetString(1);
                    var hasConversation = reader.GetBoolean(3);

                    if (!IsAllowedChatTarget(viewerRole, role)) continue;

                    var isOnline = onlineByEmail.TryGetValue(email, out var onlineStatus);
                    contacts.Add(new ChatUserStatus
                    {
                        Email = email,
                        Role = role,
                        FullName = reader.IsDBNull(2) ? email.Split('@')[0] : reader.GetString(2),
                        IsOnline = isOnline,
                        LastSeen = isOnline ? onlineStatus!.LastSeen : DateTime.MinValue,
                        HasConversation = hasConversation
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load chat contacts from database. Returning online contacts only.");
                contacts.AddRange(onlineUsers.Where(u =>
                    !string.Equals(u.Email, userEmail, StringComparison.OrdinalIgnoreCase) &&
                    IsAllowedChatTarget(viewerRole, u.Role)));
            }

            await Clients.Caller.SendAsync("ChatContacts", contacts);
        }

        private async Task JoinAcceptedGroupChatsAsync(string userEmail)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                await EnsureChatSchemaAsync(conn);
                using var cmd = new NpgsqlCommand(@"
                    SELECT gm.group_id
                    FROM chat_group_members gm
                    JOIN chat_groups g ON g.id = gm.group_id AND g.is_active = TRUE
                    WHERE LOWER(gm.user_email) = LOWER(@userEmail)
                      AND gm.status = 'accepted';", conn);
                cmd.Parameters.AddWithValue("userEmail", userEmail);
                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    await Groups.AddToGroupAsync(Context.ConnectionId, $"chat_group_{reader.GetInt64(0)}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to join persisted chat groups for {UserEmail}.", userEmail);
            }
        }

        private static async Task<int> GetAcceptedGroupCountAsync(NpgsqlConnection conn, NpgsqlTransaction transaction, string userEmail)
        {
            using var cmd = new NpgsqlCommand(@"
                SELECT COUNT(*)
                FROM chat_group_members gm
                JOIN chat_groups g ON g.id = gm.group_id AND g.is_active = TRUE
                WHERE LOWER(gm.user_email) = LOWER(@userEmail)
                  AND gm.status = 'accepted';", conn, transaction);
            cmd.Parameters.AddWithValue("userEmail", userEmail);
            return Convert.ToInt32(await cmd.ExecuteScalarAsync());
        }

        private static async Task<List<ChatGroupSummary>> GetAcceptedGroupsAsync(NpgsqlConnection conn, string userEmail)
        {
            var groups = new List<ChatGroupSummary>();
            using var cmd = new NpgsqlCommand(@"
                SELECT g.id, g.name, g.created_by, g.created_at,
                       (SELECT COUNT(*) FROM chat_group_members members WHERE members.group_id = g.id AND members.status = 'accepted') AS member_count
                FROM chat_group_members gm
                JOIN chat_groups g ON g.id = gm.group_id AND g.is_active = TRUE
                WHERE LOWER(gm.user_email) = LOWER(@userEmail)
                  AND gm.status = 'accepted'
                ORDER BY g.created_at DESC;", conn);
            cmd.Parameters.AddWithValue("userEmail", userEmail);
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                var createdBy = reader.GetString(2);
                groups.Add(new ChatGroupSummary
                {
                    Id = reader.GetInt64(0),
                    Name = reader.GetString(1),
                    CreatedBy = createdBy,
                    CreatedAt = reader.GetDateTime(3),
                    MemberCount = Convert.ToInt32(reader.GetInt64(4)),
                    IsOwner = string.Equals(createdBy, userEmail, StringComparison.OrdinalIgnoreCase)
                });
            }
            return groups;
        }

        private static async Task EnsureAcceptedGroupMemberAsync(NpgsqlConnection conn, long groupId, string userEmail)
        {
            using var cmd = new NpgsqlCommand(@"
                SELECT 1
                FROM chat_group_members gm
                JOIN chat_groups g ON g.id = gm.group_id AND g.is_active = TRUE
                WHERE gm.group_id = @groupId
                  AND LOWER(gm.user_email) = LOWER(@userEmail)
                  AND gm.status = 'accepted'
                LIMIT 1;", conn);
            cmd.Parameters.AddWithValue("groupId", groupId);
            cmd.Parameters.AddWithValue("userEmail", userEmail);
            if (await cmd.ExecuteScalarAsync() is null) throw new HubException("You are not an accepted member of this group chat.");
        }

        private async Task EnsureCanSendAsync(string receiverEmail)
        {
            var senderRole = ResolveRole();
            var receiverRole = await GetUserRoleAsync(receiverEmail);

            if (string.IsNullOrEmpty(receiverRole))
            {
                throw new HubException("The selected chat user does not exist.");
            }

            if (!IsAllowedChatTarget(senderRole, receiverRole))
            {
                throw new HubException("You are not allowed to send messages to this user.");
            }
        }

        private async Task<string> GetUserRoleAsync(string email)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand("SELECT role FROM users WHERE LOWER(email) = LOWER(@email) AND LOWER(status) = 'approved' AND is_active = TRUE LIMIT 1;", conn);
                cmd.Parameters.AddWithValue("email", email);
                return (await cmd.ExecuteScalarAsync())?.ToString() ?? string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to resolve chat receiver role for {Email}.", email);
                return string.Empty;
            }
        }

        private static bool IsAllowedChatTarget(string viewerRole, string targetRole)
        {
            var viewer = NormalizeRole(viewerRole);
            var target = NormalizeRole(targetRole);

            if (viewer == "faculty") return target == "registrar" || target == "department_admin" || target == "faculty";
            if (viewer == "department_admin") return target == "registrar" || target == "faculty";
            if (viewer == "system_admin") return target == "registrar";
            if (viewer == "registrar") return target == "system_admin" || target == "department_admin" || target == "faculty" || target == "student";
            return target == "registrar";
        }

        private static bool CanCreateGroupChat(string role)
        {
            var normalized = NormalizeRole(role);
            return normalized == "registrar" || normalized == "department_admin" || normalized == "faculty";
        }

        private IClientProxy PresenceAudience(string role)
        {
            var groups = NormalizeRole(role) switch
            {
                "system_admin" => new[] { "role_registrar" },
                "registrar" => new[] { "role_system_admin", "role_department_admin", "role_faculty", "role_student" },
                "faculty" => new[] { "role_registrar", "role_department_admin", "role_faculty" },
                "department_admin" => new[] { "role_registrar", "role_faculty" },
                _ => new[] { "role_registrar" }
            };
            return Clients.Groups(groups);
        }

        private static string NormalizeRole(string? role)
        {
            var value = (role ?? string.Empty).ToLowerInvariant();
            if (value.Contains("system_admin") || value.Contains("system admin") || value.Contains("systemadmin")) return "system_admin";
            if (value.Contains("registrar")) return "registrar";
            if (value.Contains("faculty")) return "faculty";
            if (value.Contains("deptadmin") || value.Contains("dept_admin") || value.Contains("department_admin") || value.Contains("department admin") || value.Contains("admin")) return "department_admin";
            return "student";
        }

        private string ResolveRole(string? providedRole = null)
        {
            return Context.User?.FindFirst("dbRole")?.Value
                ?? Context.User?.FindFirst(ClaimTypes.Role)?.Value
                ?? providedRole
                ?? "student";
        }

        private async Task UpdateOnlineStatus(string email, bool isOnline, string role = "")
        {
            await _chatCache.UpdateOnlineStatusAsync(email, isOnline, role, email.Split('@')[0], Context.ConnectionId);
        }
    }
}
