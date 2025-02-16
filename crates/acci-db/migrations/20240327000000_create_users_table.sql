-- Create extensions and setup
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" SCHEMA public;

-- Create schema
CREATE SCHEMA IF NOT EXISTS acci;

-- Set search path
SET search_path TO public, acci;

-- Create users table
CREATE TABLE acci.users (
    id UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- Create index on email
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
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON acci.users
    FOR EACH ROW
    EXECUTE FUNCTION acci.update_updated_at_column();
