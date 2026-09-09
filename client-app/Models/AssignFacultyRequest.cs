namespace Client_app.Models
{
    public class AssignFacultyRequest
    {
        public string Department { get; set; } = string.Empty;
        public string Section { get; set; } = string.Empty;
        public string YearLevel { get; set; } = string.Empty;
        public string? Subject { get; set; }
    }
}