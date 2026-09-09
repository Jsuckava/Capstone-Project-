-- Replace the legacy public OTP/email reset flow with an authenticated,
-- Registrar-approved password-change workflow for Faculty and Department Admins.
ALTER TABLE password_reset_requests
    ADD COLUMN IF NOT EXISTS request_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS request_reason TEXT,
    ADD COLUMN IF NOT EXISTS reviewed_by INTEGER REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS review_note TEXT,
    ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP WITH TIME ZONE;

UPDATE password_reset_requests
SET request_status = 'CANCELLED'
WHERE request_status = 'PENDING';

ALTER TABLE password_reset_requests
    DROP COLUMN IF EXISTS otp_code,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS used_at;

ALTER TABLE password_reset_requests
    DROP CONSTRAINT IF EXISTS ck_password_reset_request_status;

ALTER TABLE password_reset_requests
    ADD CONSTRAINT ck_password_reset_request_status
    CHECK (request_status IN ('PENDING', 'APPROVED', 'REJECTED', 'COMPLETED', 'CANCELLED'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_password_reset_requests_open_user
    ON password_reset_requests(user_id)
    WHERE request_status IN ('PENDING', 'APPROVED');

CREATE INDEX IF NOT EXISTS idx_password_reset_requests_status_created
    ON password_reset_requests(request_status, created_at DESC);
