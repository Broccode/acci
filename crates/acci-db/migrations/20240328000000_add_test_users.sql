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
        crypt('test123!admin', gen_salt('bf')),
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
        crypt('test123!user', gen_salt('bf')),
        'Test User',
        now(),
        now()
    )
    ON CONFLICT (email) DO NOTHING;
END;
$$;
