-- BlockGO Database Schema Initialization

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create Users table (core authentication)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    organization VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires BIGINT
);

-- Create StudentProfiles table
CREATE TABLE IF NOT EXISTS studentprofiles (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    student_no VARCHAR(50),
    department VARCHAR(100),
    section VARCHAR(50),
    year_level VARCHAR(50),
    assignment_status VARCHAR(50) DEFAULT 'Unassigned',
    date_of_birth DATE,
    phone VARCHAR(50),
    sex VARCHAR(20),
    middle_name VARCHAR(100),
    address TEXT,
    student_email VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create FacultyProfiles table
CREATE TABLE IF NOT EXISTS facultyprofiles (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    department VARCHAR(100),
    section VARCHAR(50),
    year_level VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create AdminProfiles table
CREATE TABLE IF NOT EXISTS adminprofiles (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    admin_level VARCHAR(50),
    department VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create User Requests table (registration requests)
CREATE TABLE IF NOT EXISTS userrequests (
    requestid SERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    fullname VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL,
    department VARCHAR(50),
    requeststatus VARCHAR(20) DEFAULT 'PENDING',
    createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Grade Correction Logs table
CREATE TABLE IF NOT EXISTS gradecorrectionlogs (
    logid SERIAL PRIMARY KEY,
    recordid VARCHAR(100),
    oldgrade TEXT,
    newgrade TEXT,
    reasontext TEXT,
    approvedby VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Academic Records table
CREATE TABLE IF NOT EXISTS academic_records (
    record_id SERIAL PRIMARY KEY,
    student_id VARCHAR(100) NOT NULL,
    course_code VARCHAR(50) NOT NULL,
    course_name VARCHAR(255),
    grade VARCHAR(10),
    credit_hours DECIMAL(4,2),
    semester VARCHAR(20),
    academic_year VARCHAR(10),
    status VARCHAR(50),
    faculty_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Grade Records table
CREATE TABLE IF NOT EXISTS grade_records (
    grade_id SERIAL PRIMARY KEY,
    academic_record_id INTEGER REFERENCES academic_records(record_id),
    raw_score DECIMAL(5,2),
    final_grade VARCHAR(10),
    status VARCHAR(50),
    recorded_by VARCHAR(100),
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Registration Requests table
CREATE TABLE IF NOT EXISTS registration_requests (
    registration_id SERIAL PRIMARY KEY,
    student_id VARCHAR(100) NOT NULL,
    course_id VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING',
    approved_by VARCHAR(100),
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP
);

-- Create Verification Records table
CREATE TABLE IF NOT EXISTS verification_records (
    verification_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    verification_token VARCHAR(255) UNIQUE,
    token_expires_at TIMESTAMP,
    is_verified BOOLEAN DEFAULT false,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    entity_type VARCHAR(100),
    entity_id VARCHAR(100),
    old_values TEXT,
    new_values TEXT,
    ip_address VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Canonical academic programs and versioned curriculum checklists.
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
    status VARCHAR(30) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'PENDING_APPROVAL', 'RETURNED', 'APPROVED', 'PUBLISHED', 'ARCHIVED')),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at TIMESTAMP WITH TIME ZONE,
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    registrar_comment TEXT,
    UNIQUE (program_id, curriculum_version)
);

CREATE TABLE IF NOT EXISTS curriculum_subjects (
    subject_id BIGSERIAL PRIMARY KEY,
    curriculum_id BIGINT NOT NULL REFERENCES curriculums(curriculum_id) ON DELETE CASCADE,
    subject_code VARCHAR(80) NOT NULL,
    subject_title VARCHAR(255) NOT NULL,
    units NUMERIC(5,2) NOT NULL CHECK (units > 0 AND units <= 20),
    lecture_hours NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (lecture_hours >= 0),
    laboratory_hours NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (laboratory_hours >= 0),
    prerequisite VARCHAR(255),
    year_level SMALLINT NOT NULL CHECK (year_level BETWEEN 1 AND 4),
    semester VARCHAR(20) NOT NULL CHECK (semester IN ('FIRST', 'SECOND', 'MIDYEAR')),
    subject_type VARCHAR(80),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (curriculum_id, year_level, semester, subject_code)
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

ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS curriculum_id BIGINT REFERENCES curriculums(curriculum_id) ON DELETE SET NULL;
ALTER TABLE facultyprofiles ADD COLUMN IF NOT EXISTS faculty_id VARCHAR(100);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_role VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS description TEXT;
CREATE TABLE IF NOT EXISTS gradetemplates (
    id SERIAL PRIMARY KEY,
    template_name VARCHAR(255) NOT NULL,
    department VARCHAR(100) NOT NULL,
    formula_config JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'Pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS academicsections (
    id SERIAL PRIMARY KEY,
    department VARCHAR(255) NOT NULL,
    year_level INT NOT NULL CHECK (year_level BETWEEN 1 AND 4),
    section_num INT NOT NULL CHECK (section_num > 0),
    UNIQUE (department, year_level, section_num)
);
CREATE TABLE IF NOT EXISTS facultysections (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    department VARCHAR(100) NOT NULL,
    section VARCHAR(50) NOT NULL,
    year_level VARCHAR(50),
    subject VARCHAR(100),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS shared_client_state (
    key VARCHAR(120) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);

-- Academic enrollment is period-specific. StudentProfiles remains the current
-- profile snapshot, while this table preserves enrollment history.
CREATE TABLE IF NOT EXISTS student_enrollments (
    enrollment_id BIGSERIAL PRIMARY KEY,
    student_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    student_no VARCHAR(50) NOT NULL,
    program_id INTEGER NOT NULL REFERENCES academic_programs(program_id),
    curriculum_id BIGINT REFERENCES curriculums(curriculum_id) ON DELETE SET NULL,
    academic_section_id INTEGER REFERENCES academicsections(id) ON DELETE SET NULL,
    school_year VARCHAR(20) NOT NULL,
    semester VARCHAR(20) NOT NULL CHECK (semester IN ('FIRST', 'SECOND', 'MIDYEAR')),
    year_level SMALLINT NOT NULL CHECK (year_level BETWEEN 1 AND 4),
    section VARCHAR(50),
    status VARCHAR(20) NOT NULL DEFAULT 'ENROLLED'
        CHECK (status IN ('ENROLLED', 'DROPPED', 'WITHDRAWN', 'COMPLETED')),
    enrolled_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    enrolled_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (student_user_id, school_year, semester)
);

CREATE UNIQUE INDEX idx_unique_faculty_section ON FacultySections(user_id, department, section, subject);
CREATE INDEX idx_gradetemplates_department ON GradeTemplates(department);


ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS date_of_birth DATE;
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS sex VARCHAR(20);
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS middle_name VARCHAR(100);
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE studentprofiles ADD COLUMN IF NOT EXISTS student_email VARCHAR(255);

-- Chat Messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    id SERIAL PRIMARY KEY,
    sender_email VARCHAR(100) NOT NULL,
    receiver_email VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT false,
    FOREIGN KEY (sender_email) REFERENCES users(email),
    FOREIGN KEY (receiver_email) REFERENCES users(email)
);

-- Online Status table  
CREATE TABLE IF NOT EXISTS online_status (
    email VARCHAR(100) PRIMARY KEY,
    is_online BOOLEAN DEFAULT false,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email) REFERENCES users(email)
);

-- Indexes for chat performance
CREATE INDEX IF NOT EXISTS idx_chat_messages_sender ON chat_messages(sender_email);
CREATE INDEX IF NOT EXISTS idx_chat_messages_receiver ON chat_messages(receiver_email);
CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp);
ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS chat_messages_sender_email_fkey;
ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS chat_messages_receiver_email_fkey;
ALTER TABLE online_status DROP CONSTRAINT IF EXISTS online_status_email_fkey;

CREATE INDEX IF NOT EXISTS idx_support_tickets_status_created ON support_tickets(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_tickets_registrar ON support_tickets(registrar_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_unresolved ON security_events(severity, created_at DESC) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_student_enrollments_student_period ON student_enrollments(student_user_id, school_year, semester);
CREATE INDEX IF NOT EXISTS idx_student_enrollments_program_period ON student_enrollments(program_id, school_year, semester, year_level);

-- Bulk Grade Staging table (for validation before ledger entry)
CREATE TABLE IF NOT EXISTS bulk_grade_staging (
    staging_id SERIAL PRIMARY KEY,
    batch_id VARCHAR(100) NOT NULL,
    student_hash VARCHAR(100) NOT NULL,
    course VARCHAR(100),
    subject_code VARCHAR(50),
    subject_name VARCHAR(255),
    grade VARCHAR(10),
    semester VARCHAR(20),
    school_year VARCHAR(20),
    year_level VARCHAR(10),
    section VARCHAR(50),
    faculty_id VARCHAR(100),
    status VARCHAR(50) DEFAULT 'PENDING_APPROVAL',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_active_role ON users(LOWER(role), is_active, LOWER(status));
CREATE INDEX IF NOT EXISTS idx_studentprofiles_student_no_lower ON studentprofiles(LOWER(student_no));
CREATE INDEX IF NOT EXISTS idx_adminprofiles_department_lower ON adminprofiles(LOWER(department));
CREATE INDEX IF NOT EXISTS idx_facultyprofiles_department_lower ON facultyprofiles(LOWER(department));
CREATE INDEX IF NOT EXISTS idx_facultysections_department_lower ON facultysections(LOWER(department));
CREATE INDEX IF NOT EXISTS idx_student_enrollments_latest ON student_enrollments(student_user_id, updated_at DESC, enrollment_id DESC);
CREATE INDEX IF NOT EXISTS idx_userrequests_email ON userrequests(email);
CREATE INDEX IF NOT EXISTS idx_academic_records_student ON academic_records(student_id);
CREATE INDEX IF NOT EXISTS idx_academic_records_semester ON academic_records(semester);
CREATE INDEX IF NOT EXISTS idx_grade_records_status ON grade_records(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
