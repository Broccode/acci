-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schema
CREATE SCHEMA IF NOT EXISTS acci;

-- Set search path
ALTER DATABASE acci SET search_path TO acci,public;

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA acci TO acci;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA acci TO acci;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA acci TO acci;

-- Create function to automatically update updated_at
CREATE OR REPLACE FUNCTION acci.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';
