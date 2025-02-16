-- Add sessions table
CREATE TABLE sessions (
    session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add index for user_id lookups
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

---- create above / drop below ----

DROP TABLE sessions;
