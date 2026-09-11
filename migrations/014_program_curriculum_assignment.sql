-- One active curriculum applies to every student in an academic program.
-- Per-student and intake-year curriculum values remain compatibility snapshots;
-- reads and new enrollments resolve this program-level assignment first.
CREATE TABLE IF NOT EXISTS program_curriculum_assignments (
    program_id INTEGER PRIMARY KEY REFERENCES academic_programs(program_id) ON DELETE CASCADE,
    curriculum_id BIGINT NOT NULL REFERENCES curriculums(curriculum_id) ON DELETE RESTRICT,
    assigned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO program_curriculum_assignments (program_id, curriculum_id, assigned_by)
SELECT DISTINCT ON (curriculum.program_id)
       curriculum.program_id,
       curriculum.curriculum_id,
       curriculum.created_by
FROM curriculums curriculum
WHERE curriculum.status = 'PUBLISHED'
ORDER BY curriculum.program_id,
         curriculum.published_at DESC NULLS LAST,
         curriculum.curriculum_id DESC
ON CONFLICT (program_id) DO NOTHING;

UPDATE student_enrollments enrollment
SET curriculum_id = assignment.curriculum_id,
    updated_at = CURRENT_TIMESTAMP
FROM program_curriculum_assignments assignment
WHERE assignment.program_id = enrollment.program_id
  AND enrollment.curriculum_id IS DISTINCT FROM assignment.curriculum_id;

WITH latest_enrollment AS (
    SELECT DISTINCT ON (enrollment.student_user_id)
           enrollment.student_user_id,
           enrollment.program_id
    FROM student_enrollments enrollment
    ORDER BY enrollment.student_user_id, enrollment.updated_at DESC, enrollment.enrollment_id DESC
)
UPDATE studentprofiles profile
SET curriculum_id = assignment.curriculum_id
FROM latest_enrollment latest
JOIN program_curriculum_assignments assignment ON assignment.program_id = latest.program_id
WHERE profile.user_id = latest.student_user_id
  AND profile.curriculum_id IS DISTINCT FROM assignment.curriculum_id;

CREATE INDEX IF NOT EXISTS idx_program_curriculum_assignment_curriculum
    ON program_curriculum_assignments(curriculum_id);
