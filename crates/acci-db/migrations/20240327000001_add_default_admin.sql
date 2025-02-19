-- Add default admin user migration
-- This is a one-time setup for the default admin user with password 'Admin123!@#'

-- Enable required extensions in public schema first
CREATE EXTENSION IF NOT EXISTS "pgcrypto" SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "citext" SCHEMA public;

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS acci;

-- Set search path to include both schemas
SET search_path TO acci, public;

DO $$
DECLARE
    password_hash text;
BEGIN
    -- Pre-computed Argon2 hash for password 'Admin123!@#'
    password_hash := '$argon2id$v=19$m=65536,t=2,p=1$RIyv3vbYvbZiXmBJ+hJviw$+o+MqAEY7+0gEh5bo+zKlZDhYTtT+1GhEp1Al2mcViE';

    -- Insert default admin user if it doesn't exist
    INSERT INTO acci.users (id, username, email, password_hash, is_admin, created_at, updated_at, full_name)
    VALUES (
        public.gen_random_uuid(), -- Generate UUID for id
        'admin',                  -- Username
        'admin@example.com',      -- Email
        password_hash,            -- Hashed password
        true,                     -- Is admin
        CURRENT_TIMESTAMP,        -- Created at
        CURRENT_TIMESTAMP,        -- Updated at
        'Administrator'           -- Full name
    )
    ON CONFLICT (username) DO NOTHING; -- Skip if user already exists
END $$;
