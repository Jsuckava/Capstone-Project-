using System.ComponentModel.DataAnnotations;

namespace Client_app.Models
{
    public sealed class StaffAccountRequest
    {
        [Required, StringLength(100)]
        public string StaffId { get; set; } = string.Empty;

        [Required, StringLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [StringLength(100)]
        public string? MiddleName { get; set; }

        [Required, StringLength(100)]
        public string LastName { get; set; } = string.Empty;

        [Required, EmailAddress, StringLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Role { get; set; } = string.Empty;

        [Required, StringLength(40)]
        public string ProgramCode { get; set; } = string.Empty;

        [StringLength(30)]
        public string? FacultyType { get; set; }

        [Required, MinLength(8), StringLength(128)]
        public string Password { get; set; } = string.Empty;
    }

    public sealed class RegistrarAccountRequest
    {
        [Required, StringLength(100)]
        public string RegistrarId { get; set; } = string.Empty;

        [Required, StringLength(200)]
        public string FullName { get; set; } = string.Empty;

        [Required, EmailAddress, StringLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required, MinLength(8), StringLength(128)]
        public string Password { get; set; } = string.Empty;
    }

    public sealed class UpdateRegistrarAccountRequest
    {
        [EmailAddress, StringLength(255)]
        public string? Email { get; set; }

        [MinLength(8), StringLength(128)]
        public string? Password { get; set; }

        public bool? IsActive { get; set; }
    }

    public sealed class ManualPasswordResetRequest
    {
        [Required, MinLength(8), StringLength(128)]
        public string NewPassword { get; set; } = string.Empty;
    }

    public sealed record ManagedAccountResult(
        int Id,
        string AccountId,
        string FullName,
        string Email,
        string Role,
        string Status,
        bool IsActive,
        string? Department,
        bool BlockchainAuditRecorded,
        string? Warning = null);
}
