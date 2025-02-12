-- Add default admin user migration
-- This is a one-time setup for the default admin user with password 'whiskey'

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS acci;

-- Enable required extensions if not already enabled
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$
DECLARE
    password_hash text;
BEGIN
    -- Generate hash for password 'whiskey'
    -- Using pgcrypto's crypt function with blowfish method
    password_hash := public.crypt('whiskey', public.gen_salt('bf', 8));

    -- Insert default admin user if it doesn't exist
    INSERT INTO acci.users (id, email, password_hash, full_name, created_at, updated_at)
    VALUES (
        public.gen_random_uuid(), -- Generate UUID for id
        'admin',                  -- Username
        password_hash,            -- Hashed password
        'Default Admin',          -- Full name
        CURRENT_TIMESTAMP,        -- Created at
        CURRENT_TIMESTAMP         -- Updated at
    )
    ON CONFLICT (email) DO NOTHING; -- Skip if user already exists
END $$;
