CREATE TABLE IF NOT EXISTS chat_conversation_states (
    user_email VARCHAR(255) NOT NULL,
    other_user_email VARCHAR(255) NOT NULL,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_email, other_user_email),
    CONSTRAINT chat_conversation_states_different_users
        CHECK (LOWER(user_email) <> LOWER(other_user_email))
);

CREATE INDEX IF NOT EXISTS idx_chat_conversation_states_user_updated
    ON chat_conversation_states(LOWER(user_email), updated_at DESC);
