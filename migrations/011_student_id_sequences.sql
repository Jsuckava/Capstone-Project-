CREATE TABLE IF NOT EXISTS student_id_sequences (
    enrollment_year INTEGER PRIMARY KEY CHECK (enrollment_year BETWEEN 2000 AND 9999),
    last_sequence INTEGER NOT NULL CHECK (last_sequence BETWEEN 0 AND 9999),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO student_id_sequences (enrollment_year, last_sequence)
SELECT
    2000 + LEFT(student_no, 2)::INTEGER,
    MAX(RIGHT(student_no, 4)::INTEGER)
FROM studentprofiles
WHERE student_no ~ '^[0-9]{2}-[0-9]{4}$'
GROUP BY LEFT(student_no, 2)
ON CONFLICT (enrollment_year) DO UPDATE
SET last_sequence = GREATEST(student_id_sequences.last_sequence, EXCLUDED.last_sequence),
    updated_at = CURRENT_TIMESTAMP;
