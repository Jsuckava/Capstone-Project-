using System.Text.Json.Serialization;

namespace BlockGo.Models
{
    public class AcademicRecord
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("student_hash")]
        public string StudentHash { get; set; } = string.Empty;

        [JsonPropertyName("student_id")]
        public string StudentId { get; set; } = string.Empty;

        [JsonPropertyName("student_no")]
        public string StudentNo { get; set; } = string.Empty;

        [JsonPropertyName("student_name")]
        public string StudentName { get; set; } = string.Empty;

        [JsonPropertyName("section")]
        public string Section { get; set; } = string.Empty;

        [JsonPropertyName("year_level")]
        public string YearLevel { get; set; } = string.Empty;

        [JsonPropertyName("course")]
        public string Course { get; set; } = string.Empty;

        [JsonPropertyName("program")]
        public string Program { get; set; } = string.Empty;

        [JsonPropertyName("subject_code")]
        public string SubjectCode { get; set; } = string.Empty;

        [JsonPropertyName("subject_title")]
        public string SubjectTitle { get; set; } = string.Empty;

        [JsonPropertyName("units")]
        public decimal Units { get; set; }

        [JsonPropertyName("grade")]
        public string Grade { get; set; } = string.Empty;

        [JsonPropertyName("semester")]
        public string Semester { get; set; } = string.Empty;

        [JsonPropertyName("school_year")]
        public string SchoolYear { get; set; } = string.Empty;

        [JsonPropertyName("term")]
        public string Term { get; set; } = string.Empty;

        [JsonPropertyName("faculty_id")]
        public string FacultyId { get; set; } = string.Empty;

        [JsonPropertyName("professor_name")]
        public string ProfessorName { get; set; } = string.Empty;

        [JsonPropertyName("date")]
        public string Date { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; } = string.Empty;

        [JsonPropertyName("submitted_by")]
        public string SubmittedBy { get; set; } = string.Empty;

        [JsonPropertyName("transaction_id")]
        public string TransactionId { get; set; } = string.Empty;

        [JsonPropertyName("transaction_hash")]
        public string TransactionHash { get; set; } = string.Empty;

        [JsonPropertyName("ipfs_cid")]
        public string IpfsCid { get; set; } = string.Empty;

        [JsonPropertyName("university")]
        public string University { get; set; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("note")]
        public string? Note { get; set; }

        [JsonPropertyName("version")]
        public int Version { get; set; }
    }
}
