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
        -- Argon2 hash for password 'test123!admin'
        '$argon2id$v=19$m=19456,t=2,p=1$RrTX4YlRhno4/ke6vrjuqw$NCm1O/25fMVGOtfByYsXz9yPYe8ygG/64Z1c+AmWLf8',
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
        -- Argon2 hash for password 'test123!user'
        '$argon2id$v=19$m=19456,t=2,p=1$N9ezyp8m0ej5g5M/2vz54w$09jm71ioibQPRMQU/wl6vpilsha63nB+fG1eB0yObig',
        'Test User',
        now(),
        now()
    )
    ON CONFLICT (email) DO NOTHING;
END;
$$;
