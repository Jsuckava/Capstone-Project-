using BlockGo.Models;
using Client_app.Models;
using For_Testing_Only_Capstone.Models;


namespace BlockGo.Mappers
{
    public static class GradeMapper
    {
        public static AcademicRecord ToBlockchainRecord(this GradeRequest request, string university = "PLV")
        {
            string uniqueRecordId = Guid.NewGuid().ToString(); // Use a unique ID for each record
            return new AcademicRecord
            {
                Id = uniqueRecordId, 
                StudentHash = request.StudentHash,
                StudentId = request.StudentId,
                StudentNo = request.StudentId,
                StudentName = request.StudentName,
                Section = request.Section,
                YearLevel = request.YearLevel,
                Course = request.Course,
                Program = string.IsNullOrWhiteSpace(request.Program) ? request.Course ?? string.Empty : request.Program,
                SubjectCode = request.SubjectCode,
                SubjectTitle = request.SubjectName,
                Units = request.Units,
                Grade = request.Grade,
                Semester = request.Semester,
                SchoolYear = request.SchoolYear,
                Term = request.Term,
                FacultyId = request.FacultyId,
                ProfessorName = request.ProfessorName,
                Date = request.Date,
                SubmittedBy = request.FacultyId,
                University = university,
                IpfsCid = request.IpfsCID ?? "",
                Status = "FINALIZED",
                Version = 1
            };
        }

        public static Gradecorrectionlog ToInitialLog(this GradeRequest request)
        {
            return new Gradecorrectionlog
            {
                Recordid = request.StudentId,
                Newgrade = request.Grade,
                Reasontext = "Initial Grade Recording",
                Approvedby = request.FacultyId,
                Timestamp = DateTime.UtcNow
            };
        }
    }
}
