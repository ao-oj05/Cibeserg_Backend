-- Ejecutar como administrador después de aplicar las migraciones.
GRANT CONNECT ON DATABASE scandev_db TO migrator, app_user;
GRANT USAGE ON SCHEMA public TO migrator, app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
REVOKE UPDATE, DELETE ON TABLE public.audit_logs FROM app_user;
REVOKE ALL ON TABLE public._prisma_migrations FROM app_user;

ALTER DEFAULT PRIVILEGES FOR ROLE migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
