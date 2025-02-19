-- Add full_name column to users table
ALTER TABLE acci.users ADD COLUMN full_name VARCHAR(255) NOT NULL DEFAULT '';

-- Update existing users to have a default full_name based on their username
UPDATE acci.users SET full_name = username WHERE full_name = '';

-- Remove the default value constraint
ALTER TABLE acci.users ALTER COLUMN full_name DROP DEFAULT;
