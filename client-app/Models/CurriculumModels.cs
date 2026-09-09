using System.ComponentModel.DataAnnotations;

namespace Client_app.Models
{
    public static class CurriculumStatuses
    {
        public const string Draft = "DRAFT";
        public const string PendingApproval = "PENDING_APPROVAL";
        public const string Returned = "RETURNED";
        public const string Approved = "APPROVED";
        public const string Published = "PUBLISHED";
        public const string Archived = "ARCHIVED";
    }

    public static class CurriculumSemesters
    {
        public const string First = "FIRST";
        public const string Second = "SECOND";
        public const string Midyear = "MIDYEAR";
        public static readonly IReadOnlySet<string> All = new HashSet<string> { First, Second, Midyear };
    }

    public sealed class CreateCurriculumRequest
    {
        [Required, StringLength(40)] public string ProgramCode { get; set; } = string.Empty;
        [Required, StringLength(100)] public string CurriculumCode { get; set; } = string.Empty;
        [Required, StringLength(255)] public string CurriculumName { get; set; } = string.Empty;
        [Required, StringLength(100)] public string CurriculumVersion { get; set; } = string.Empty;
        [StringLength(50)] public string? SchoolYear { get; set; }
    }

    public sealed class UpdateCurriculumRequest
    {
        [Required, StringLength(100)] public string CurriculumCode { get; set; } = string.Empty;
        [Required, StringLength(255)] public string CurriculumName { get; set; } = string.Empty;
        [Required, StringLength(100)] public string CurriculumVersion { get; set; } = string.Empty;
        [StringLength(50)] public string? SchoolYear { get; set; }
    }

    public sealed class CurriculumSubjectRequest
    {
        [Required, StringLength(80)] public string SubjectCode { get; set; } = string.Empty;
        [Required, StringLength(255)] public string SubjectTitle { get; set; } = string.Empty;
        [Range(0.01, 20)] public decimal Units { get; set; }
        [Range(0, 40)] public decimal LectureHours { get; set; }
        [Range(0, 40)] public decimal LaboratoryHours { get; set; }
        [StringLength(255)] public string? Prerequisite { get; set; }
        [Range(1, 4)] public int YearLevel { get; set; }
        [Required] public string Semester { get; set; } = string.Empty;
        [StringLength(80)] public string? SubjectType { get; set; }
    }

    public sealed class ReturnCurriculumRequest
    {
        [Required, StringLength(2000), MinLength(3)] public string Reason { get; set; } = string.Empty;
    }

    public sealed class AssignStudentCurriculumRequest
    {
        [Required, EmailAddress] public string StudentEmail { get; set; } = string.Empty;
    }

    public sealed class CurriculumSubjectDto
    {
        public long SubjectId { get; set; }
        public string SubjectCode { get; set; } = string.Empty;
        public string SubjectTitle { get; set; } = string.Empty;
        public decimal Units { get; set; }
        public decimal LectureHours { get; set; }
        public decimal LaboratoryHours { get; set; }
        public string? Prerequisite { get; set; }
        public int YearLevel { get; set; }
        public string Semester { get; set; } = string.Empty;
        public string? SubjectType { get; set; }
    }

    public sealed class CurriculumDto
    {
        public long CurriculumId { get; set; }
        public string CurriculumCode { get; set; } = string.Empty;
        public string CurriculumName { get; set; } = string.Empty;
        public int ProgramId { get; set; }
        public string ProgramCode { get; set; } = string.Empty;
        public string ProgramName { get; set; } = string.Empty;
        public string CurriculumVersion { get; set; } = string.Empty;
        public string? SchoolYear { get; set; }
        public string Status { get; set; } = string.Empty;
        public string CreatedBy { get; set; } = string.Empty;
        public string CreatedByName { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
        public DateTimeOffset? SubmittedAt { get; set; }
        public string? ReviewedBy { get; set; }
        public DateTimeOffset? ReviewedAt { get; set; }
        public DateTimeOffset? PublishedAt { get; set; }
        public string? RegistrarComment { get; set; }
        public IReadOnlyCollection<CurriculumSubjectDto> Subjects { get; set; } = Array.Empty<CurriculumSubjectDto>();
        public decimal TotalUnits => Subjects.Sum(subject => subject.Units);
    }
}
