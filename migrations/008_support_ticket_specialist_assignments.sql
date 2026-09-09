ALTER TABLE support_tickets
    ADD COLUMN IF NOT EXISTS assigned_specialist VARCHAR(40);

ALTER TABLE support_tickets
    DROP CONSTRAINT IF EXISTS ck_support_ticket_specialist;

ALTER TABLE support_tickets
    ADD CONSTRAINT ck_support_ticket_specialist
    CHECK (
        assigned_specialist IS NULL OR assigned_specialist IN (
            'IT_ADMIN',
            'FRONTEND_DEVELOPER',
            'BACKEND_DEVELOPER',
            'NETWORK_SPECIALIST'
        )
    );
