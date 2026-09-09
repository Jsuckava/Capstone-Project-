using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Client_app.Models
{
    public class ChatMessage
    {
        [Key]
        public int Id { get; set; }
        
        public string SenderEmail { get; set; } = string.Empty;
        
        public string ReceiverEmail { get; set; } = string.Empty;
        
        public string Message { get; set; } = string.Empty;
        
        public DateTime Timestamp { get; set; }

        public DateTime SentAt { get; set; }

        public DateTime? DeliveredAt { get; set; }

        public DateTime? SeenAt { get; set; }

        public string? AttachmentName { get; set; }

        public string? AttachmentMime { get; set; }

        public long? AttachmentSizeBytes { get; set; }

        [JsonIgnore]
        public byte[]? AttachmentData { get; set; }

        public string? AttachmentDataBase64 { get; set; }
        
        public bool IsRead { get; set; } = false;
        
        [JsonIgnore]
        public string? ConnectionId { get; set; }
    }
    
    public class ChatUserStatus
    {
        public string Email { get; set; } = string.Empty;
        public bool IsOnline { get; set; }
        public DateTime LastSeen { get; set; }
        public string Role { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public bool HasConversation { get; set; }
    }

    public class ChatConversationState
    {
        public string OtherUserEmail { get; set; } = string.Empty;
        public bool IsArchived { get; set; }
        public DateTime? DeletedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class ChatGroupSummary
    {
        public long Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string CreatedBy { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public int MemberCount { get; set; }
        public bool IsOwner { get; set; }
    }

    public class ChatGroupInvitation
    {
        public long GroupId { get; set; }
        public string GroupName { get; set; } = string.Empty;
        public string InvitedBy { get; set; } = string.Empty;
        public DateTime InvitedAt { get; set; }
        public int MemberCount { get; set; }
    }

    public class ChatGroupMessage
    {
        public long Id { get; set; }
        public long GroupId { get; set; }
        public string SenderEmail { get; set; } = string.Empty;
        public string SenderName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public DateTime SentAt { get; set; }
    }
}
