CREATE UNIQUE INDEX IF NOT EXISTS uq_studentprofiles_student_no_lower
    ON studentprofiles (LOWER(BTRIM(student_no)))
    WHERE NULLIF(BTRIM(student_no), '') IS NOT NULL;

CREATE OR REPLACE FUNCTION prevent_enrolled_student_number_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NULLIF(BTRIM(OLD.student_no), '') IS NOT NULL
       AND NEW.student_no IS DISTINCT FROM OLD.student_no THEN
        RAISE EXCEPTION 'Student ID cannot be changed after the student has been enrolled.';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_studentprofiles_immutable_student_no ON studentprofiles;

CREATE TRIGGER trg_studentprofiles_immutable_student_no
BEFORE UPDATE OF student_no ON studentprofiles
FOR EACH ROW
EXECUTE FUNCTION prevent_enrolled_student_number_change();
