-- Enable required extensions in public schema first
CREATE EXTENSION IF NOT EXISTS "pgcrypto" SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "citext" SCHEMA public;

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS acci;

-- Set search path to include both schemas
SET search_path TO acci, public;

-- Create users table with case-insensitive username
DROP TABLE IF EXISTS acci.users CASCADE;
CREATE TABLE acci.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username CITEXT UNIQUE NOT NULL,
    email CITEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    full_name TEXT NOT NULL
);

-- Create indexes
CREATE INDEX users_username_idx ON acci.users (username);
CREATE INDEX users_email_idx ON acci.users (email);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION acci.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON acci.users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON acci.users
    FOR EACH ROW
    EXECUTE FUNCTION acci.update_updated_at_column();
