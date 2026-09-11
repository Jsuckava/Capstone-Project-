DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM studentprofiles
        WHERE NULLIF(BTRIM(full_name), '') IS NOT NULL
        GROUP BY LOWER(REGEXP_REPLACE(BTRIM(full_name), '\s+', ' ', 'g'))
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'Duplicate normalized student names already exist. Resolve them before applying migration 015.';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_studentprofiles_normalized_full_name
    ON studentprofiles ((LOWER(REGEXP_REPLACE(BTRIM(full_name), '\s+', ' ', 'g'))))
    WHERE NULLIF(BTRIM(full_name), '') IS NOT NULL;
