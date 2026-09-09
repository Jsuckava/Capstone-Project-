using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Client_app.Models
{
    public class SignupRequest
    {
        public string FullName { get; set; } = string.Empty;
        
        public string Email { get; set; } = string.Empty;
        
        public string Password { get; set; } = string.Empty; // Will be DOB mm/dd/yyyy for students
        
        public string Role { get; set; } = "student";
        
        public string VerificationCode { get; set; } = string.Empty;
        
        public string Department { get; set; } = string.Empty;

        public string? FacultyType { get; set; }
        
        public string? StudentNo { get; set; }
        
        // NEW: Date of Birth for students (format: mm/dd/yyyy → becomes password)
        public string? DateOfBirth { get; set; }
    }
}

