# Enrollment import regression checks

Run with .NET 8 from the repository root:

```powershell
dotnet run --project tests/EnrollmentImportChecks/EnrollmentImportChecks.csproj
```

The executable links the production `StudentEnrollmentFile` parser and checks template birthdate aliases, quoted/multiline CSV, BOM handling, delimiter detection, and malformed input. A failed assertion exits unsuccessfully. It needs no database, blockchain, or credentials.

To additionally validate the supplied 21-row template example plus 20 added students, pass its local path after `--`. The checks read the file without saving its contents or enrolling students:

```powershell
dotnet run --project tests/EnrollmentImportChecks/EnrollmentImportChecks.csproj -- "C:/Users/DELL/Downloads/student-enrollment-2026-2027-with-20-added.csv"
```

The checks also cover optional Section Number values and conflicts with full Section values. Pass the six-row optional-sections test CSV as a second argument to validate its expected three assigned and three unassigned students.
