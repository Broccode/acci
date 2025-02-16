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
        '$argon2id$v=19$m=19456,t=2,p=1$bWZ+4wr5tLx4QEM3trx2Pg$JBl1MRvzGpkLZLXfcDERIuunFrM1lnuhwCofQ8K0Upw',
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
        '$argon2id$v=19$m=19456,t=2,p=1$6kt4HvpGuCqECDBt1ePaAw$fANvyM7qvr1D/0+onffWc7IMIFEM9eeuKJD8ELamUnw',
        'Test User',
        now(),
        now()
    )
    ON CONFLICT (email) DO NOTHING;
END;
$$;
