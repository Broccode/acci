-- Add migration script here

-- Add is_active column to users table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'acci'
        AND table_name = 'users'
        AND column_name = 'is_active'
    ) THEN
        ALTER TABLE acci.users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT true;

        -- Update existing users to be active
        UPDATE acci.users SET is_active = true WHERE is_active IS NULL;
    END IF;
END $$;
