-- Set search path
SET search_path TO public, acci;

-- Drop existing indexes if they exist
DROP INDEX IF EXISTS acci.sessions_user_id_idx;
DROP INDEX IF EXISTS acci.sessions_expires_at_idx;

-- Drop existing table if it exists
DROP TABLE IF EXISTS acci.sessions CASCADE;

-- Create sessions table
CREATE TABLE acci.sessions (
    id UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES acci.users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Create indexes
CREATE INDEX sessions_user_id_idx ON acci.sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON acci.sessions (expires_at);

-- Create cleanup function
CREATE OR REPLACE FUNCTION acci.cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM acci.sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
