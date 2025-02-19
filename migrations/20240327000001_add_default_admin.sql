-- Add default admin user with password 'whiskey123!'
INSERT INTO users (username, is_admin, password_hash)
VALUES ('admin', true, '$argon2id$v=19$m=19456,t=2,p=1$cL6CLjkSf+hW/Ef7ub1b3A$R7Ra8j1Fzyy5Df6V14wCMr3bMtSUMJbxVVgissnpX6M')
ON CONFLICT (username) DO NOTHING;
