-- Additive schema for managed accounts, enriched grade records, and curricula.
-- This migration is intentionally idempotent so it can be applied to existing
-- installations whose runtime-created tables differ slightly.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS academic_programs (
    program_id SERIAL PRIMARY KEY,
    program_code VARCHAR(40) NOT NULL UNIQUE,
    program_name VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO academic_programs (program_code, program_name) VALUES
    ('BECED', 'Bachelor of Early Childhood Education'),
    ('BSED-ENG', 'Bachelor of Secondary Education Major in English'),
    ('BSED-FIL', 'Bachelor of Secondary Education Major in Filipino'),
    ('BSED-MATH', 'Bachelor of Secondary Education Major in Mathematics'),
    ('BSED-SCI', 'Bachelor of Secondary Education Major in Science'),
    ('BSED-SOCSTUD', 'Bachelor of Secondary Education Major in Social Studies'),
    ('BSCE', 'Bachelor of Science in Civil Engineering'),
    ('BSEE', 'Bachelor of Science in Electrical Engineering'),
    ('BSIT', 'Bachelor of Science in Information Technology'),
    ('BAC', 'Bachelor of Arts in Communication'),
    ('BSP', 'Bachelor of Science in Psychology'),
    ('BSSW', 'Bachelor of Science in Social Work'),
    ('BPA', 'Bachelor of Public Administration'),
    ('BSA', 'Bachelor of Science in Accountancy'),
    ('BSBA-FM', 'Bachelor of Science in Business Administration Major in Financial Management'),
    ('BSBA-HRM', 'Bachelor of Science in Business Administration Major in Human Resource Management'),
    ('BSBA-MM', 'Bachelor of Science in Business Administration Major in Marketing Management')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS curriculums (
    curriculum_id BIGSERIAL PRIMARY KEY,
    curriculum_code VARCHAR(100) NOT NULL UNIQUE,
    curriculum_name VARCHAR(255) NOT NULL,
    program_id INTEGER NOT NULL REFERENCES academic_programs(program_id),
    curriculum_version VARCHAR(100) NOT NULL,
    school_year VARCHAR(50),
    status VARCHAR(30) NOT NULL DEFAULT 'DRAFT',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at TIMESTAMP WITH TIME ZONE,
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    registrar_comment TEXT,
    CONSTRAINT ck_curriculums_status CHECK (
        status IN ('DRAFT', 'PENDING_APPROVAL', 'RETURNED', 'APPROVED', 'PUBLISHED', 'ARCHIVED')
    ),
    CONSTRAINT uq_curriculum_program_version UNIQUE (program_id, curriculum_version)
);

CREATE TABLE IF NOT EXISTS curriculum_subjects (
    subject_id BIGSERIAL PRIMARY KEY,
    curriculum_id BIGINT NOT NULL REFERENCES curriculums(curriculum_id) ON DELETE CASCADE,
    subject_code VARCHAR(80) NOT NULL,
    subject_title VARCHAR(255) NOT NULL,
    units NUMERIC(5,2) NOT NULL,
    lecture_hours NUMERIC(5,2) NOT NULL DEFAULT 0,
    laboratory_hours NUMERIC(5,2) NOT NULL DEFAULT 0,
    prerequisite VARCHAR(255),
    year_level SMALLINT NOT NULL,
    semester VARCHAR(20) NOT NULL,
    subject_type VARCHAR(80),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_curriculum_subject_year CHECK (year_level BETWEEN 1 AND 4),
    CONSTRAINT ck_curriculum_subject_semester CHECK (semester IN ('FIRST', 'SECOND', 'MIDYEAR')),
    CONSTRAINT ck_curriculum_subject_units CHECK (units > 0 AND units <= 20),
    CONSTRAINT ck_curriculum_subject_hours CHECK (lecture_hours >= 0 AND laboratory_hours >= 0),
    CONSTRAINT uq_curriculum_subject_slot UNIQUE (curriculum_id, year_level, semester, subject_code)
);

CREATE TABLE IF NOT EXISTS support_tickets (
    ticket_id BIGSERIAL PRIMARY KEY,
    registrar_id INTEGER NOT NULL REFERENCES users(id),
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'NORMAL',
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    admin_response TEXT,
    handled_by INTEGER REFERENCES users(id),
    assigned_specialist VARCHAR(40),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT ck_support_ticket_severity CHECK (severity IN ('LOW', 'NORMAL', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_support_ticket_status CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED')),
    CONSTRAINT ck_support_ticket_specialist CHECK (assigned_specialist IS NULL OR assigned_specialist IN ('IT_ADMIN', 'FRONTEND_DEVELOPER', 'BACKEND_DEVELOPER', 'NETWORK_SPECIALIST'))
);

CREATE TABLE IF NOT EXISTS password_reset_requests (
    request_id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_password_reset_requests_email
    ON password_reset_requests(LOWER(email), created_at DESC);

CREATE TABLE IF NOT EXISTS security_events (
    security_event_id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    attempted_identity VARCHAR(255),
    ip_address VARCHAR(100),
    request_path VARCHAR(500),
    request_method VARCHAR(20),
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by INTEGER REFERENCES users(id),
    CONSTRAINT ck_security_event_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS curriculum_id BIGINT;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_studentprofiles_curriculum'
    ) THEN
        ALTER TABLE studentprofiles
            ADD CONSTRAINT fk_studentprofiles_curriculum
            FOREIGN KEY (curriculum_id) REFERENCES curriculums(curriculum_id) ON DELETE SET NULL;
    END IF;
END $$;

ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS subject_title VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS professor_name VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS program VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS term VARCHAR(20);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS units NUMERIC(5,2);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS submitted_by VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS recorded_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS transaction_hash VARCHAR(255);

ALTER TABLE facultyprofiles ADD COLUMN IF NOT EXISTS faculty_id VARCHAR(100);

-- Older persistent databases created audit_logs with only user_id, action,
-- details, and timestamp. CREATE TABLE IF NOT EXISTS in the base schema does
-- not add the canonical columns required by AuditLogService.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entity_type VARCHAR(100);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entity_id VARCHAR(100);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS old_values TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS new_values TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_role VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS description TEXT;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'audit_logs'
          AND column_name = 'details'
    ) THEN
        EXECUTE '
            UPDATE audit_logs
            SET description = COALESCE(description, details)
            WHERE description IS NULL AND details IS NOT NULL';
    END IF;
END $$;

-- Chat participants are identified by account email, and System Admin may rename
-- a Registrar login. ChatHub already manages these rows without foreign keys;
-- keep the migration consistent so historical conversations can be migrated.
ALTER TABLE IF EXISTS chat_messages DROP CONSTRAINT IF EXISTS chat_messages_sender_email_fkey;
ALTER TABLE IF EXISTS chat_messages DROP CONSTRAINT IF EXISTS chat_messages_receiver_email_fkey;
ALTER TABLE IF EXISTS online_status DROP CONSTRAINT IF EXISTS online_status_email_fkey;

CREATE INDEX IF NOT EXISTS idx_curriculums_program_status
    ON curriculums(program_id, status);
CREATE INDEX IF NOT EXISTS idx_curriculums_created_by
    ON curriculums(created_by);
CREATE INDEX IF NOT EXISTS idx_curriculum_subjects_curriculum
    ON curriculum_subjects(curriculum_id, year_level, semester);
CREATE INDEX IF NOT EXISTS idx_studentprofiles_curriculum
    ON studentprofiles(curriculum_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity
    ON audit_logs(entity_type, entity_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pending_grade_student_period
    ON pending_grade_records(student_hash, school_year, semester, term);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status_created
    ON support_tickets(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_tickets_registrar
    ON support_tickets(registrar_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_created
    ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_unresolved
    ON security_events(severity, created_at DESC) WHERE resolved_at IS NULL;
