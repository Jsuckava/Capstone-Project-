using System.Globalization;
using System.Text.RegularExpressions;
using CsvHelper;
using CsvHelper.Configuration;
using Client_app.Models;

namespace Client_app.Services;

public static class FacultyAccountFile
{
    public sealed record FacultyAccountRow(int RowNumber, StaffAccountRequest Account);

    private static readonly IReadOnlyDictionary<string, string> HeaderAliases =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["faculty_id"] = "staff_id",
            ["employee_id"] = "staff_id",
            ["id"] = "staff_id",
            ["firstname"] = "first_name",
            ["middlename"] = "middle_name",
            ["lastname"] = "last_name",
            ["program"] = "program_code",
            ["department"] = "program_code",
            ["type"] = "faculty_type",
            ["password"] = "temporary_password",
            ["temp_password"] = "temporary_password"
        };

    private static readonly string[] RequiredHeaders =
        { "staff_id", "first_name", "last_name", "email", "program_code", "temporary_password" };

    public static List<FacultyAccountRow> ReadCsv(TextReader reader, int maximumRows = 200)
    {
        var configuration = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            DetectDelimiter = true,
            DetectDelimiterValues = new[] { ",", ";", "\t" },
            TrimOptions = TrimOptions.Trim,
            ExceptionMessagesContainRawData = false
        };
        using var csv = new CsvReader(reader, configuration);
        if (!csv.Read()) throw new ArgumentException("The faculty account file is empty.");
        csv.ReadHeader();
        var headers = (csv.HeaderRecord ?? Array.Empty<string>()).Select(NormalizeHeader).ToArray();
        if (headers.Any(string.IsNullOrWhiteSpace) || headers.Distinct(StringComparer.OrdinalIgnoreCase).Count() != headers.Length)
            throw new ArgumentException("Faculty account column headings must be non-empty and unique.");
        var missing = RequiredHeaders.Where(required => !headers.Contains(required, StringComparer.OrdinalIgnoreCase)).ToArray();
        if (missing.Length > 0)
            throw new ArgumentException($"Missing required faculty account columns: {string.Join(", ", missing)}.");

        var rows = new List<FacultyAccountRow>();
        while (csv.Read())
        {
            if (rows.Count >= maximumRows)
                throw new ArgumentException($"A faculty account upload can contain at most {maximumRows} rows.");
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var index = 0; index < headers.Length; index++)
                values[headers[index]] = index < csv.Parser.Count ? csv.GetField(index)?.Trim() ?? string.Empty : string.Empty;
            if (values.Values.All(string.IsNullOrWhiteSpace)) continue;
            rows.Add(new FacultyAccountRow(csv.Parser.Row, new StaffAccountRequest
            {
                StaffId = Value(values, "staff_id"),
                FirstName = Value(values, "first_name"),
                MiddleName = OptionalValue(values, "middle_name"),
                LastName = Value(values, "last_name"),
                Email = Value(values, "email"),
                Role = "faculty",
                ProgramCode = Value(values, "program_code"),
                FacultyType = OptionalValue(values, "faculty_type") ?? "Regular",
                Password = Value(values, "temporary_password")
            }));
        }
        if (rows.Count == 0) throw new ArgumentException("The faculty account file has headings but no account rows.");
        return rows;
    }

    private static string NormalizeHeader(string value)
    {
        var normalized = Regex.Replace(value.Trim().Trim('\uFEFF').ToLowerInvariant(), @"[^a-z0-9]+", "_").Trim('_');
        return HeaderAliases.TryGetValue(normalized, out var canonical) ? canonical : normalized;
    }

    private static string Value(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var value) ? value : string.Empty;

    private static string? OptionalValue(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
}
