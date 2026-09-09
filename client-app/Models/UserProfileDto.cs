using System.Collections.Generic;

namespace Client_app.Models
{
    public class UserProfileDto
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string FullName { get; set; }
        public string Role { get; set; }
        public string Status { get; set; }
        public string? Department { get; set; }
        public string? StudentNo { get; set; }
        public string? Section { get; set; }
        public string? DateOfBirth { get; set; }
        public string? StudentEmail { get; set; }
        public string? MiddleName { get; set; }
        public string? Phone { get; set; }
        public string? Address { get; set; }
        public string? Sex { get; set; }
        public string? YearLevel { get; set; }
        public long? CurriculumId { get; set; }
        public string? CurriculumName { get; set; }
        public string? CurriculumVersion { get; set; }
        public string? SchoolYear { get; set; }
        public string? Semester { get; set; }
        public string? EnrollmentStatus { get; set; }
        public string? FacultyType { get; set; }
        public List<string>? EnrolledSubjects { get; set; }
    }
}
