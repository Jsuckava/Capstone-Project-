using System.ComponentModel.DataAnnotations;

namespace Client_app.Models
{
    public sealed class CreateSupportTicketRequest
    {
        [Required, StringLength(5000, MinimumLength = 10)]
        public string Description { get; set; } = string.Empty;

        [Required]
        public string AssignedSpecialist { get; set; } = string.Empty;
    }

    public sealed class UpdateSupportTicketRequest
    {
        [Required]
        public string Status { get; set; } = string.Empty;

        [StringLength(5000)]
        public string? AdminResponse { get; set; }

        [Required]
        public string AssignedSpecialist { get; set; } = string.Empty;
    }

    public sealed class BroadcastSupportNoticeRequest
    {
        [Required, StringLength(1000, MinimumLength = 3)]
        public string Message { get; set; } = string.Empty;
    }
}
