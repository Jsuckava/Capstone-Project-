using System;
using System.Collections.Generic;
using CsvHelper.Configuration;

namespace Client_app.Models
{
    public class BulkGradeRecord
    {
        public string student_id { get; set; } = string.Empty;
        public string course { get; set; } = string.Empty;
        public string section { get; set; } = string.Empty;
        public string subject_code { get; set; } = string.Empty;
        public string grade { get; set; } = string.Empty;
        public string semester { get; set; } = string.Empty;
        public string school_year { get; set; } = string.Empty;
        public string date { get; set; } = string.Empty;
    }

    public class BulkUploadError
    {
        public string StudentId { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
    }

    public class BulkGradeRecordMap : ClassMap<BulkGradeRecord>
    {
        public BulkGradeRecordMap()
        {
            Map(m => m.student_id).Name("student_id").Optional();
            Map(m => m.course).Name("course").Optional();
            Map(m => m.section).Name("section").Optional();
            Map(m => m.subject_code).Name("subject_code").Optional();
            Map(m => m.grade).Name("grade").Optional();
            Map(m => m.semester).Name("semester").Optional();
            Map(m => m.school_year).Name("school_year").Optional();
            Map(m => m.date).Name("date").Optional();
        }
    }
}
