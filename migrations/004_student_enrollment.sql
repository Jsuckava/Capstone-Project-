-- Durable, period-specific student enrollment records.
-- StudentProfiles remains the current-profile snapshot used by existing pages.

CREATE TABLE IF NOT EXISTS academicsections (
    id SERIAL PRIMARY KEY,
    department VARCHAR(255) NOT NULL,
    year_level INT NOT NULL CHECK (year_level BETWEEN 1 AND 4),
    section_num INT NOT NULL CHECK (section_num > 0),
    UNIQUE (department, year_level, section_num)
);

ALTER TABLE academicsections ALTER COLUMN department TYPE VARCHAR(255);

CREATE TABLE IF NOT EXISTS student_enrollments (
    enrollment_id BIGSERIAL PRIMARY KEY,
    student_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    student_no VARCHAR(50) NOT NULL,
    program_id INTEGER NOT NULL REFERENCES academic_programs(program_id),
    curriculum_id BIGINT REFERENCES curriculums(curriculum_id) ON DELETE SET NULL,
    academic_section_id INTEGER REFERENCES academicsections(id) ON DELETE SET NULL,
    school_year VARCHAR(20) NOT NULL,
    semester VARCHAR(20) NOT NULL,
    year_level SMALLINT NOT NULL,
    section VARCHAR(50),
    status VARCHAR(20) NOT NULL DEFAULT 'ENROLLED',
    enrolled_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    enrolled_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_student_enrollment_semester
        CHECK (semester IN ('FIRST', 'SECOND', 'MIDYEAR')),
    CONSTRAINT ck_student_enrollment_year
        CHECK (year_level BETWEEN 1 AND 4),
    CONSTRAINT ck_student_enrollment_status
        CHECK (status IN ('ENROLLED', 'DROPPED', 'WITHDRAWN', 'COMPLETED')),
    CONSTRAINT uq_student_enrollment_period
        UNIQUE (student_user_id, school_year, semester)
);

CREATE INDEX IF NOT EXISTS idx_student_enrollments_student_period
    ON student_enrollments(student_user_id, school_year, semester);
CREATE INDEX IF NOT EXISTS idx_student_enrollments_program_period
    ON student_enrollments(program_id, school_year, semester, year_level);
