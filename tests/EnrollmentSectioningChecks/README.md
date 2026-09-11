# Enrollment to Section Creation

Enrollment records are authoritative in `student_enrollments`, with
`student_user_id -> users.id`, `program_id -> academic_programs.program_id`,
`curriculum_id -> curriculums.curriculum_id`, and nullable
`academic_section_id -> academicsections.id`. A new enrollment without a supplied
section has `status = 'ENROLLED'`, `academic_section_id = NULL`, and `section = NULL`.
`StudentProfiles` is the current academic-period snapshot, not an enrollment history.

Use the existing numbered migrations, including `004_student_enrollment.sql`,
`011_student_id_sequences.sql`, `012_curriculum_batch_assignments.sql`, and
`013_unassigned_enrollment_lookup.sql`, through the project's normal migration
process. No new table or migration is required by this fix. Old accounts without
enrollment records need an enrollment with their actual program and academic period;
account approval alone is not enough to infer that information safely.

## Registrar endpoints

All requests require a registrar JWT and use the existing `/api/Auth` gateway.

```http
GET /api/Auth/students/unassigned-enrolled?department=BSIT&schoolYear=2026-2027&semester=FIRST&yearLevel=1
```

All filters are optional; omitting them returns all eligible unassigned enrollment
periods. Program codes and full names are accepted. The response is
`{ "status": "Success", "data": [...] }`. Each row includes `id` (user ID),
`enrollmentId`, `studentNo`, `fullName`, `department`, `yearLevel`,
`enrollmentStatus`, `academicSectionId`, `schoolYear`, and `semester`.
The query requires `status = 'ENROLLED' AND academic_section_id IS NULL`,
joined to an active, approved student account and its profile.

Create/reuse a section through the existing section endpoints, then assign saved IDs:

```http
POST /api/Auth/sections/7/assign-students
Content-Type: application/json

{"studentIds":["26-0001","26-0002"],"schoolYear":"2026-2027","semester":"FIRST"}
```

The response is `{ "status": "Success", "assignedCount": 2 }`.
School year and semester are required. The entire assignment request rolls back if
any student is ineligible. Missing sections return 404; enrollment conflicts return
409; invalid inputs return 400. Retrying the same assignment is safe. Assigning a
student who already belongs to another section is rejected unless an intentional
move supplies `expectedSectionIds`, for example `{"26-0001": 3}`. This must match
the student's saved section; stale moves are rejected. Move/Shuffle uses this
check automatically after the first save. The endpoint does not create accounts, enroll new periods, or
register Fabric wallets. Multiple section requests may commit separately; retrying
after a later request fails preserves earlier successful assignments.

## UI workflow and checks

1. In Student Enrollment, choose program, school year, semester, year level, and
   curriculum. Upload the existing template or use Manual Entry. A section is optional.
   New students without an ID receive a number from the existing sequence table;
   repeat uploads resolve an existing student by email.
2. Open Section Creation and choose the same program, school-year start, semester,
   and year level. The enrolled roster loads automatically. The Auto-Populate button
   refreshes it without importing another file.
3. Generate Sections. Saved student numbers are assigned to those sections in the
   selected period. Verify that the assigned students disappear from the unassigned
   query and that current student/faculty views receive the updated profile section.
4. Verify a second semester remains independently assignable, and that inactive,
   dropped, withdrawn, completed, wrong-program, and wrong-year students are rejected.

Legacy shared JSON rosters without an academic period are not sufficient for official
assignment. Enroll those students for the correct period and load that roster first.

Run the database checks against a disposable PostgreSQL database:

```powershell
$env:SECTIONING_TEST_CONNECTION = 'Host=localhost;Database=sectioning_tests;Username=postgres;Password=...'
dotnet run --project tests/EnrollmentSectioningChecks
dotnet run --project tests/EnrollmentImportChecks
```

The database checks create and remove only a uniquely named test schema and cover
eligibility, period/program filters, rollback, idempotency, profile snapshots, and
competing assignments. They do not exercise a live Fabric network or browser session.

Frontend regression checks:

```powershell
cd frontend
npm test -- --watchAll=false --runInBand --runTestsByPath src/components/registrar/RegistrarStudentSectioning.test.jsx src/components/registrar/StudentEnrollmentManagement.test.jsx src/utils/registrarSectioningBackendSync.test.js src/utils/studentSectioningHelpers.test.js
```
