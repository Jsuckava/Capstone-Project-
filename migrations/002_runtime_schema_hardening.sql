-- Migration: Move request-time schema creation into database migrations
-- Purpose: Auth, sectioning, settings, chat, and staged-grade controllers assume this schema exists.

CREATE TABLE IF NOT EXISTS academicsections (
    id SERIAL PRIMARY KEY,
    department VARCHAR(50) NOT NULL,
    year_level INT NOT NULL,
    section_num INT NOT NULL,
    UNIQUE(department, year_level, section_num)
);

ALTER TABLE facultyprofiles ADD COLUMN IF NOT EXISTS faculty_type VARCHAR(20);
ALTER TABLE facultysections ADD COLUMN IF NOT EXISTS subject VARCHAR(100);
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_faculty_section
    ON facultysections(user_id, department, section, subject);

CREATE TABLE IF NOT EXISTS systemsettings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sectioningstate (
    key VARCHAR(100) PRIMARY KEY,
    data_json JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pending_grade_records (
    id VARCHAR(255) PRIMARY KEY,
    student_hash VARCHAR(255),
    section VARCHAR(100),
    course VARCHAR(255),
    subject_code VARCHAR(100),
    grade TEXT,
    semester VARCHAR(50),
    school_year VARCHAR(50),
    faculty_id VARCHAR(255),
    date VARCHAR(50),
    ipfs_cid VARCHAR(255),
    status VARCHAR(50),
    note TEXT
);

ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS id VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS student_hash VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS section VARCHAR(100);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS course VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS subject_code VARCHAR(100);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS grade TEXT;
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS semester VARCHAR(50);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS school_year VARCHAR(50);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS faculty_id VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS date VARCHAR(50);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS ipfs_cid VARCHAR(255);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS status VARCHAR(50);
ALTER TABLE pending_grade_records ADD COLUMN IF NOT EXISTS note TEXT;
ALTER TABLE pending_grade_records ALTER COLUMN grade TYPE TEXT;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'pending_grade_records' AND column_name = 'batch_id') THEN
        ALTER TABLE pending_grade_records ALTER COLUMN batch_id DROP NOT NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'pending_grade_records' AND column_name = 'student_id') THEN
        ALTER TABLE pending_grade_records ALTER COLUMN student_id DROP NOT NULL;
    END IF;
END $$;

DO $$
DECLARE
    constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'pending_grade_records'::regclass
          AND contype = 'c'
    LOOP
        EXECUTE format('ALTER TABLE pending_grade_records DROP CONSTRAINT IF EXISTS %I', constraint_name);
    END LOOP;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'pending_grade_records' AND column_name = 'blockchain_record_id'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'pending_grade_records' AND column_name = 'record_id'
    ) THEN
        UPDATE pending_grade_records
        SET id = COALESCE(NULLIF(id, ''), NULLIF(blockchain_record_id, ''), record_id::text)
        WHERE id IS NULL OR id = '';
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'pending_grade_records' AND column_name = 'record_id'
    ) THEN
        UPDATE pending_grade_records
        SET id = COALESCE(NULLIF(id, ''), record_id::text)
        WHERE id IS NULL OR id = '';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_grade_records_id
    ON pending_grade_records(id);

CREATE UNIQUE INDEX IF NOT EXISTS unique_grade_entry
    ON pending_grade_records(student_hash, subject_code, school_year, semester);

CREATE TABLE IF NOT EXISTS chat_messages (
    id SERIAL PRIMARY KEY,
    sender_email VARCHAR(100) NOT NULL,
    receiver_email VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT false
);

ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT false;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_name VARCHAR(255);
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_mime VARCHAR(100);
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_size_bytes BIGINT;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachment_data BYTEA;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS seen_at TIMESTAMP WITH TIME ZONE;

UPDATE chat_messages
SET sent_at = COALESCE(sent_at, timestamp, CURRENT_TIMESTAMP)
WHERE sent_at IS NULL;

UPDATE chat_messages
SET timestamp = COALESCE(timestamp, sent_at, CURRENT_TIMESTAMP)
WHERE timestamp IS NULL;

CREATE INDEX IF NOT EXISTS idx_chat_messages_sender ON chat_messages(sender_email);
CREATE INDEX IF NOT EXISTS idx_chat_messages_receiver ON chat_messages(receiver_email);
CREATE INDEX IF NOT EXISTS idx_chat_messages_sent_at ON chat_messages(sent_at);
CREATE INDEX IF NOT EXISTS idx_chat_messages_pair_sent_at
    ON chat_messages(LOWER(sender_email), LOWER(receiver_email), sent_at);
