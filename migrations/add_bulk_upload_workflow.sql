-- Migration: Add Bulk Upload Approval Workflow
-- Purpose: Implement 3-stage approval for bulk grade uploads (Faculty -> DeptAdmin -> Registrar)

CREATE TABLE IF NOT EXISTS bulk_grade_uploads (
    upload_id SERIAL PRIMARY KEY,
    batch_id UUID UNIQUE DEFAULT gen_random_uuid(),
    faculty_email VARCHAR(255) NOT NULL,
    faculty_department VARCHAR(255) NOT NULL,
    total_records INTEGER DEFAULT 0,
    successful_records INTEGER DEFAULT 0,
    failed_records INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'PENDING_APPROVAL' CHECK (status IN ('PENDING_APPROVAL', 'APPROVED_BY_DEPT', 'FINALIZED_BY_REGISTRAR', 'REJECTED')),
    ipfs_cid VARCHAR(255),
    semester VARCHAR(50),
    school_year VARCHAR(10),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_by_dept_email VARCHAR(255),
    approved_by_dept_at TIMESTAMP,
    finalized_by_registrar_email VARCHAR(255),
    finalized_by_registrar_at TIMESTAMP,
    rejection_reason TEXT,
    rejected_at TIMESTAMP,
    rejected_by_email VARCHAR(255),
    FOREIGN KEY (faculty_email) REFERENCES Users(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pending_grade_records (
    record_id SERIAL PRIMARY KEY,
    batch_id UUID NOT NULL,
    student_id VARCHAR(255) NOT NULL,
    student_email VARCHAR(255),
    grade VARCHAR(10) NOT NULL,
    subject_code VARCHAR(50),
    subject_name VARCHAR(255),
    course VARCHAR(255),
    status VARCHAR(50) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'FINALIZED', 'REJECTED')),
    blockchain_record_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (batch_id) REFERENCES bulk_grade_uploads(batch_id) ON DELETE CASCADE,
    FOREIGN KEY (student_email) REFERENCES Users(email) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_bulk_uploads_status ON bulk_grade_uploads(status);
CREATE INDEX idx_bulk_uploads_faculty ON bulk_grade_uploads(faculty_email);
CREATE INDEX idx_pending_grades_batch ON pending_grade_records(batch_id);
CREATE INDEX idx_pending_grades_status ON pending_grade_records(status);
