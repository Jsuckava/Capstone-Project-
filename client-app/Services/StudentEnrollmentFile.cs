using System.Globalization;
using System.Text.RegularExpressions;
using CsvHelper;
using CsvHelper.Configuration;

namespace Client_app.Services;

public static class StudentEnrollmentFile
{
    public static string ResolveSection(string? section, string? number, short yearLevel)
    {
        var fullSection = NormalizeSection(section, yearLevel, required: false);
        if (string.IsNullOrWhiteSpace(number)) return fullSection;
        if (!Regex.IsMatch(number.Trim(), @"^[0-9]+$") ||
            !int.TryParse(number.Trim(), out var sectionNumber) || sectionNumber < 1)
            throw new ArgumentException("Section Number must be a positive whole number, or blank for manual sectioning later.");
        var numberedSection = $"{yearLevel}-{sectionNumber}";
        if (fullSection.Length > 0 && fullSection != numberedSection)
            throw new ArgumentException("Section and Section Number refer to different sections. Use matching values or leave one blank.");
        return numberedSection;
    }

    public static string NormalizeSection(string? value, short yearLevel, bool required = true)
    {
        var section = (value ?? "").Trim();
        if (!required && section.Length == 0) return "";
        var match = Regex.Match(section, @"^([1-4])\s*-\s*(\d+)$");
        if (!match.Success || !int.TryParse(match.Groups[2].Value, out var sectionNumber) || sectionNumber < 1)
            throw new ArgumentException("Section must use the year-section format, for example 2-1.");
        if (short.Parse(match.Groups[1].Value) != yearLevel)
            throw new ArgumentException("Section year must match the selected year level.");
        return $"{yearLevel}-{sectionNumber}";
    }

    public static string NormalizeHeader(string value)
    {
        var header = Regex.Replace(value.Trim().Trim('\uFEFF').ToLowerInvariant(), @"[^a-z0-9]+", "_").Trim('_');
        return header is "birthdate" or "birth_date" or "birthday" or "dob" ? "date_of_birth" : header;
    }

    public static (HashSet<string> Headers, List<Dictionary<string, string>> Records) ReadCsv(TextReader reader)
    {
        if (reader.Peek() == '\uFEFF') reader.Read();
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            DetectDelimiter = true,
            DetectDelimiterValues = new[] { ",", ";", "\t" },
            TrimOptions = TrimOptions.Trim,
            ExceptionMessagesContainRawData = false,
        };
        using var csv = new CsvReader(reader, config);
        if (!csv.Read()) throw new ArgumentException("The enrollment file is empty.");
        csv.ReadHeader();
        var rawColumns = (csv.HeaderRecord ?? Array.Empty<string>()).Select(NormalizeHeader).ToArray();
        int lastNonEmpty = rawColumns.Length - 1;
        while (lastNonEmpty >= 0 && string.IsNullOrWhiteSpace(rawColumns[lastNonEmpty]))
        {
            lastNonEmpty--;
        }
        var columns = lastNonEmpty >= 0 ? rawColumns.Take(lastNonEmpty + 1).ToArray() : rawColumns;
        var headers = new HashSet<string>(columns, StringComparer.OrdinalIgnoreCase);
        if (headers.Contains("") || headers.Count != columns.Length)
            throw new ArgumentException("Enrollment column headings must be non-empty and unique.");
        var records = new List<Dictionary<string, string>>();
        while (csv.Read())
        {
            if (csv.Parser.Count < columns.Length)
                throw new ArgumentException($"Row {csv.Parser.Row} has {csv.Parser.Count} values; expected at least {columns.Length}. Quote values containing commas.");
            if (Enumerable.Range(columns.Length, csv.Parser.Count - columns.Length)
                .Any(index => !string.IsNullOrWhiteSpace(csv.GetField(index))))
                throw new ArgumentException($"Row {csv.Parser.Row} has values without column headings. Quote values containing commas.");
            var record = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var index = 0; index < columns.Length; index++) record[columns[index]] = csv.GetField(index)?.Trim() ?? "";
            records.Add(record);
        }
        if (records.Count == 0) throw new ArgumentException("The enrollment file has headings but no student rows.");
        return (headers, records);
    }
}
