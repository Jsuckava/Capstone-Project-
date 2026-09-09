using System.Text.Json.Serialization;

namespace BlockGo.Models
{
    public sealed class BlockchainAuditEvent
    {
        [JsonPropertyName("event_type")]
        public string EventType { get; set; } = string.Empty;

        [JsonPropertyName("entity_id")]
        public string EntityId { get; set; } = string.Empty;

        [JsonPropertyName("actor_id")]
        public string ActorId { get; set; } = string.Empty;

        [JsonPropertyName("actor_role")]
        public string ActorRole { get; set; } = string.Empty;

        [JsonPropertyName("changed_fields")]
        public IReadOnlyCollection<string> ChangedFields { get; set; } = Array.Empty<string>();

        [JsonPropertyName("description")]
        public string? Description { get; set; }
    }
}
