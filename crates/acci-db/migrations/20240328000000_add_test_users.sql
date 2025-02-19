-- Only add test users in development/test environments
DO $$
BEGIN
    -- Skip if not in development/test
    IF NOT current_setting('app.environment', TRUE) IN ('development', 'test') THEN
        RETURN;
    END IF;

    -- Enable required extensions in public schema first
    CREATE EXTENSION IF NOT EXISTS "pgcrypto" SCHEMA public;
    CREATE EXTENSION IF NOT EXISTS "citext" SCHEMA public;

    -- Create schema if not exists
    CREATE SCHEMA IF NOT EXISTS acci;

    -- Set search path to include both schemas
    SET search_path TO acci, public;

    -- Test Admin User
    INSERT INTO acci.users (id, username, email, password_hash, is_admin, created_at, updated_at, full_name)
    VALUES (
        gen_random_uuid(),
        'test_admin',
        'test.admin@example.com',
        -- Hash for 'Admin123!@#'
        '$argon2id$v=19$m=65536,t=2,p=1$HLkrp+ZbF3uqDQjTducBOA$CuIAcKQPyFc20XWFzhDbL9aYmCjzyQTOvFqkukhw0WE',
        true,
        now(),
        now(),
        'Test Administrator'
    )
    ON CONFLICT (username) DO UPDATE SET
        email = EXCLUDED.email,
        password_hash = EXCLUDED.password_hash,
        is_admin = EXCLUDED.is_admin,
        full_name = EXCLUDED.full_name;

    -- Regular Test User
    INSERT INTO acci.users (id, username, email, password_hash, is_admin, created_at, updated_at, full_name)
    VALUES (
        gen_random_uuid(),
        'test_user',
        'test.user@example.com',
        -- Hash for 'Test123!@#'
        '$argon2id$v=19$m=65536,t=2,p=1$vFRFwY2wOgOfH/bBTVHroA$d/nRBBt72P2iNYmNXK1OCZ3b0dpxqHJW08Hyc6wvx68',
        false,
        now(),
        now(),
        'Test User'
    )
    ON CONFLICT (username) DO UPDATE SET
        email = EXCLUDED.email,
        password_hash = EXCLUDED.password_hash,
        is_admin = EXCLUDED.is_admin,
        full_name = EXCLUDED.full_name;
END;
$$;
