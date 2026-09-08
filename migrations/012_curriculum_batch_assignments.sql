ALTER TABLE studentprofiles
    ADD COLUMN IF NOT EXISTS batch_year INTEGER;

ALTER TABLE student_enrollments
    ADD COLUMN IF NOT EXISTS batch_year INTEGER;

UPDATE studentprofiles
SET batch_year = 2000 + LEFT(student_no, 2)::INTEGER
WHERE batch_year IS NULL
  AND student_no ~ '^[0-9]{2}-[0-9]{4}$';

UPDATE student_enrollments enrollment
SET batch_year = COALESCE(
    profile.batch_year,
    CASE WHEN enrollment.school_year ~ '^[0-9]{4}-[0-9]{4}$'
         THEN SPLIT_PART(enrollment.school_year, '-', 1)::INTEGER END
)
FROM studentprofiles profile
WHERE profile.user_id = enrollment.student_user_id
  AND enrollment.batch_year IS NULL;

CREATE TABLE IF NOT EXISTS curriculum_batch_assignments (
    program_id INTEGER NOT NULL REFERENCES academic_programs(program_id) ON DELETE CASCADE,
    batch_year INTEGER NOT NULL CHECK (batch_year BETWEEN 2000 AND 9999),
    curriculum_id BIGINT NOT NULL REFERENCES curriculums(curriculum_id) ON DELETE RESTRICT,
    assigned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (program_id, batch_year)
);

INSERT INTO curriculum_batch_assignments (program_id, batch_year, curriculum_id)
SELECT candidate.program_id, candidate.batch_year, candidate.curriculum_id
FROM (
    SELECT DISTINCT ON (enrollment.program_id, enrollment.batch_year)
        enrollment.program_id,
        enrollment.batch_year,
        enrollment.curriculum_id
    FROM student_enrollments enrollment
    JOIN curriculums curriculum
      ON curriculum.curriculum_id = enrollment.curriculum_id
     AND curriculum.program_id = enrollment.program_id
    WHERE enrollment.batch_year IS NOT NULL
      AND enrollment.curriculum_id IS NOT NULL
    ORDER BY enrollment.program_id, enrollment.batch_year,
             enrollment.updated_at DESC, enrollment.enrollment_id DESC
) candidate
ON CONFLICT (program_id, batch_year) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_studentprofiles_batch
    ON studentprofiles (batch_year, department);

CREATE INDEX IF NOT EXISTS idx_student_enrollments_batch
    ON student_enrollments (program_id, batch_year, updated_at DESC);
