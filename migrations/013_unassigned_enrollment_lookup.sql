-- The enrollment table already owns student_user_id -> users(id),
-- academic_section_id -> academicsections(id), and the ENROLLED status constraint.
-- Query the period-specific record, not the mutable StudentProfiles snapshot.
CREATE INDEX IF NOT EXISTS idx_student_enrollments_unassigned
    ON student_enrollments (school_year, semester, program_id, year_level, student_no)
    WHERE status = 'ENROLLED' AND academic_section_id IS NULL;
