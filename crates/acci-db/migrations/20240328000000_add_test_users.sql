-- Only add test users in development/test environments
DO $$
BEGIN
    -- Skip if not in development/test
    IF NOT current_setting('app.environment', TRUE) IN ('development', 'test') THEN
        RETURN;
    END IF;

    -- Test Admin User
    INSERT INTO acci.users (id, email, password_hash, full_name, created_at, updated_at)
    VALUES (
        gen_random_uuid(),
        'test.admin@example.com',
        -- Pre-computed Argon2 hash for password 'test123!admin'
        '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$QWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=',
        'Test Administrator',
        now(),
        now()
    )
    ON CONFLICT (email) DO NOTHING;

    -- Regular Test User
    INSERT INTO acci.users (id, email, password_hash, full_name, created_at, updated_at)
    VALUES (
        gen_random_uuid(),
        'test.user@example.com',
        -- Pre-computed Argon2 hash for password 'test123!user'
        '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$UVdFUlRZVUlPUEFTREZHSEpLTFpYQ1ZCTk0xMjM0NTY3ODk=',
        'Test User',
        now(),
        now()
    )
    ON CONFLICT (email) DO NOTHING;
END;
$$;
