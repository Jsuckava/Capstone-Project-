using Client_app.Services;
using System.Globalization;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

foreach (var alias in new[] { "Birthdate", "Birth Date", "Birthday", "DOB", "Date of Birth", "date_of_birth" })
{
    Check(StudentEnrollmentFile.NormalizeHeader(alias) == "date_of_birth", $"Unrecognized birthdate heading: {alias}");
    var parsed = StudentEnrollmentFile.ReadCsv(new StringReader($"First Name,Last Name,{alias}\nTest,Student,05/15/2005\n"));
    Check(parsed.Records[0]["date_of_birth"] == "05/15/2005", "Birthdate was not preserved.");
}

var quoted = StudentEnrollmentFile.ReadCsv(new StringReader("\uFEFF\"First Name\",\"Last Name\",\"Birthdate\",\"Home Address\"\n\"Test\",\"Student\",\"2005-05-15\",\"Unit 1, Block 2; City\nSecond line\"\n"));
Check(quoted.Records.Count == 1, "Quoted multiline field split into multiple students.");
Check(quoted.Records[0]["home_address"] == "Unit 1, Block 2; City\nSecond line", "Quoted address was corrupted.");
foreach (var separator in new[] { ";", "\t" })
{
    var parsed = StudentEnrollmentFile.ReadCsv(new StringReader($"First Name{separator}Birthdate\nTest{separator}05/15/2005\n"));
    Check(parsed.Records[0]["date_of_birth"] == "05/15/2005", "Delimiter detection failed.");
}
foreach (var invalid in new[] { "", "First Name,Birthdate\n", "First Name,Birthdate\nTest,05/15/2005,extra\n", "Birthdate,DOB\n05/15/2005,05/15/2005\n" })
{
    var rejected = false;
    try { StudentEnrollmentFile.ReadCsv(new StringReader(invalid)); }
    catch (ArgumentException) { rejected = true; }
    Check(rejected, "Malformed/empty enrollment input was accepted.");
}
Console.WriteLine("PASS: birthdate aliases, quoted/multiline CSV, delimiters, and invalid-file checks.");

foreach (short year in new short[] { 1, 2, 3, 4 })
{
    foreach (var blank in new string?[] { null, "", "  " })
        Check(StudentEnrollmentFile.NormalizeSection(blank, year, required: false) == "", "Enrollment must allow students awaiting section assignment.");
    Check(StudentEnrollmentFile.NormalizeSection($" {year} - 01 ", year, required: false) == $"{year}-1", "Supplied section normalization failed.");
}
foreach (var invalid in new[] { "2-1", "1-0", "1-A", "unassigned", "5-1" })
{
    var rejected = false;
    try { StudentEnrollmentFile.NormalizeSection(invalid, 1, required: false); }
    catch (ArgumentException) { rejected = true; }
    Check(rejected, "Invalid/mismatched supplied section was accepted.");
}
var missingAssignmentRejected = false;
try { StudentEnrollmentFile.NormalizeSection("", 1); }
catch (ArgumentException) { missingAssignmentRejected = true; }
Check(missingAssignmentRejected, "Explicit section assignment must still require a section.");
Console.WriteLine("PASS: sectionless enrollment in all four year levels; explicit sections remain validated.");

if (args.Length > 0)
{
    using var reader = File.OpenText(args[0]);
    var supplied = StudentEnrollmentFile.ReadCsv(reader);
    Check(supplied.Records.Count == 21, "Expected the template example plus 20 added students.");
    foreach (var row in supplied.Records)
    {
        Check(!string.IsNullOrWhiteSpace(row["first_name"]) && !string.IsNullOrWhiteSpace(row["last_name"]), "Student name missing.");
        Check(DateTime.TryParseExact(row["date_of_birth"], "MM/dd/yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out _), "Student birthdate invalid.");
        Check(StudentEnrollmentFile.NormalizeSection(row.GetValueOrDefault("section"), 1, required: false) == "", "Template must enroll without a section.");
    }
    Console.WriteLine($"PASS: supplied enrollment file — {supplied.Records.Count} rows with valid names and birthdates; no password column needed.");
}

foreach (short year in new short[] { 1, 2, 3, 4 }) {
    Check(StudentEnrollmentFile.ResolveSection(null, " 02 ", year) == $"{year}-2", "Optional section number must use the student's year level.");
    Check(StudentEnrollmentFile.ResolveSection(null, "", year) == "", "Blank section number must allow later assignment.");
}
Check(StudentEnrollmentFile.ResolveSection("1-2", "2", 1) == "1-2", "Matching columns should be accepted.");
foreach (var invalid in new[] { "0", "-1", "1.5", "1-2", "abc", "2147483648" }) {
    var rejected = false;
    try { StudentEnrollmentFile.ResolveSection(null, invalid, 1); }
    catch (ArgumentException) { rejected = true; }
    Check(rejected, "Invalid section number accepted.");
}
try { StudentEnrollmentFile.ResolveSection("1-1", "2", 1); throw new Exception("Conflicting section columns accepted."); }
catch (ArgumentException) { }
if (args.Length > 1) {
    var sample = StudentEnrollmentFile.ReadCsv(File.OpenText(args[1]));
    Check(sample.Records.Count == 6, "Expected six manual-test students.");
    var sections = sample.Records.Select(row => StudentEnrollmentFile.ResolveSection(null, row["section_number"], 1)).ToArray();
    Check(sections.SequenceEqual(new[] { "1-1", "1-1", "1-2", "", "", "" }), "Manual-test CSV section assignments differ.");
    foreach (var row in sample.Records)
        Check(DateTime.TryParseExact(row["date_of_birth"], "MM/dd/yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out _), "Invalid sample birthdate.");
}
Console.WriteLine("PASS: optional section numbers, blank sections, conflicts, invalid numbers, and manual-test CSV.");
