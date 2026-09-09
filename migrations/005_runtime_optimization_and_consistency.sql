-- Complete compatibility columns that older databases previously received
-- from request-time controller DDL, then index the actual lookup patterns.

ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS date_of_birth DATE;
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS sex VARCHAR(20);
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS middle_name VARCHAR(100);
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS student_email VARCHAR(255);

ALTER TABLE facultyprofiles ADD COLUMN IF NOT EXISTS faculty_type VARCHAR(20);
ALTER TABLE facultysections ADD COLUMN IF NOT EXISTS subject VARCHAR(100);

ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS student_no VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS student_name VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS subject_title VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS professor_name VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS program VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS term VARCHAR(20);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS units NUMERIC(5,2);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS submitted_by VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS recorded_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS transaction_hash VARCHAR(255);
ALTER TABLE pending_grade_records ALTER COLUMN grade TYPE TEXT;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'gradecorrectionlogs') THEN
        ALTER TABLE gradecorrectionlogs
            ALTER COLUMN oldgrade TYPE TEXT,
            ALTER COLUMN newgrade TYPE TEXT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS shared_client_state (
    key VARCHAR(120) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);

-- The application upserts by section as well as academic period.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'pending_grade_records'::regclass
          AND conname = 'unique_grade_entry'
    ) THEN
        ALTER TABLE pending_grade_records DROP CONSTRAINT unique_grade_entry;
    END IF;
END $$;
DROP INDEX IF EXISTS unique_grade_entry;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'pending_grade_records'::regclass
          AND conname = 'unique_grade_entry_section'
    ) THEN
        ALTER TABLE pending_grade_records
            ADD CONSTRAINT unique_grade_entry_section
            UNIQUE (student_hash, subject_code, school_year, semester, section);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_users_email_lower
    ON users (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_active_role
    ON users (LOWER(role), is_active, LOWER(status));
CREATE INDEX IF NOT EXISTS idx_studentprofiles_student_no_lower
    ON studentprofiles (LOWER(student_no));
CREATE INDEX IF NOT EXISTS idx_adminprofiles_department_lower
    ON adminprofiles (LOWER(department));
CREATE INDEX IF NOT EXISTS idx_facultyprofiles_department_lower
    ON facultyprofiles (LOWER(department));
CREATE INDEX IF NOT EXISTS idx_facultysections_department_lower
    ON facultysections (LOWER(department));
CREATE INDEX IF NOT EXISTS idx_pending_grade_lookup
    ON pending_grade_records (
        LOWER(student_hash), LOWER(subject_code), school_year, semester, LOWER(section)
    );
CREATE INDEX IF NOT EXISTS idx_pending_grade_faculty_status
    ON pending_grade_records (LOWER(faculty_id), status);
CREATE INDEX IF NOT EXISTS idx_student_enrollments_latest
    ON student_enrollments (student_user_id, updated_at DESC, enrollment_id DESC);
CREATE INDEX IF NOT EXISTS idx_chat_messages_retention
    ON chat_messages (COALESCE(sent_at, timestamp));
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_timestamp
    ON audit_logs (action, timestamp DESC);
