-- Ejecutar dentro de scandev_db como administrador de PostgreSQL.
-- La base debe existir previamente. Define contraseñas de login con \password.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migrator') THEN
    CREATE ROLE migrator LOGIN;
  ELSE
    ALTER ROLE migrator LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user LOGIN;
  ELSE
    ALTER ROLE app_user LOGIN;
  END IF;
END $$;

GRANT CONNECT ON DATABASE scandev_db TO migrator, app_user;
GRANT USAGE, CREATE ON SCHEMA public TO migrator;
GRANT USAGE ON SCHEMA public TO app_user;
