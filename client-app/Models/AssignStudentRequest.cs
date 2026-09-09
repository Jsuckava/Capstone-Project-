namespace Client_app.Models
{
    public class AssignStudentRequest
    {
        public string Department { get; set; } = string.Empty;
        public string Section { get; set; } = string.Empty;
        public string? YearLevel { get; set; }
        public string? SchoolYear { get; set; }
        public string? Semester { get; set; }
        public long? CurriculumId { get; set; }
    }
}
