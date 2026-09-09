using System.Text.Json.Serialization;

namespace BlockGo.Models
{
    public class GradeRequest
    {
        [JsonPropertyName("student_id")]
        public string StudentId { get; set; } = string.Empty;

        [JsonPropertyName("student_name")]
        public string StudentName { get; set; } = string.Empty;
        
        [JsonPropertyName("course")]
        public string Course { get; set; } = string.Empty;

        [JsonPropertyName("student_hash")]
        public string StudentHash { get; set; } = string.Empty;

        [JsonPropertyName("subject_code")]
        public string SubjectCode { get; set; } = string.Empty;

        [JsonPropertyName("subject_name")]
        public string SubjectName { get; set; } = string.Empty;

        [JsonPropertyName("professor_name")]
        public string ProfessorName { get; set; } = string.Empty;

        [JsonPropertyName("program")]
        public string Program { get; set; } = string.Empty;

        [JsonPropertyName("term")]
        public string Term { get; set; } = string.Empty;

        [JsonPropertyName("units")]
        public decimal Units { get; set; }

        [JsonPropertyName("section")]
        public string Section { get; set; } = string.Empty;

        [JsonPropertyName("year_level")]
        public string YearLevel { get; set; } = string.Empty;

        [JsonPropertyName("grade")]
        public string Grade { get; set; } = string.Empty;

        [JsonPropertyName("semester")]
        public string Semester { get; set; } = string.Empty;

        [JsonPropertyName("school_year")]
        public string SchoolYear { get; set; } = string.Empty;

        [JsonPropertyName("faculty_id")]
        public string FacultyId { get; set; } = string.Empty;

        [JsonPropertyName("date")]
        public string Date { get; set; } = string.Empty;

        [JsonPropertyName("ipfs_cid")]
        public string? IpfsCID { get; set; }
    }
}
