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
    -- Pre-computed Argon2 hash for password 'whiskey'
    password_hash := '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$WScssxqkuNGE4lp2sphIWXiKJYI94xUUA9L4wgUuhxc';

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
