ALTER TABLE "users"
  ADD CONSTRAINT "users_password_hash_format_chk"
  CHECK (
    "passwordHash" ~ '^\$argon2id\$'
    OR "passwordHash" ~ '^\$2[aby]\$(1[2-9]|2[0-9]|3[01])\$'
  ),
  ADD CONSTRAINT "users_email_lowercase_chk"
  CHECK ("email" = lower("email"));

ALTER TABLE "scans"
  ADD CONSTRAINT "scans_host_chk"
  CHECK ("host" <> '' AND "host" = lower("host")),
  ADD CONSTRAINT "scans_score_range_chk"
  CHECK ("riskScore" BETWEEN 0 AND 100),
  ADD CONSTRAINT "scans_risk_matches_score_chk"
  CHECK (
    "riskLevel" = (
      CASE
        WHEN "riskScore" >= 80 THEN 'SAFE'
        WHEN "riskScore" >= 60 THEN 'WARNING'
        ELSE 'CRITICAL'
      END
    )::"RiskLevel"
  ),
  ADD CONSTRAINT "scans_response_time_chk"
  CHECK ("responseTimeMs" IS NULL OR "responseTimeMs" >= 0),
  ADD CONSTRAINT "scans_time_order_chk"
  CHECK ("completedAt" IS NULL OR "completedAt" >= "startedAt"),
  ADD CONSTRAINT "scans_raw_headers_chk"
  CHECK (
    "rawHeaders" IS NULL
    OR (jsonb_typeof("rawHeaders") = 'object' AND octet_length("rawHeaders"::text) <= 4096)
  );

ALTER TABLE "findings"
  ADD CONSTRAINT "findings_passed_is_info_chk"
  CHECK ("status" <> 'PASSED' OR "severity" = 'INFO'),
  ADD CONSTRAINT "findings_check_key_format_chk"
  CHECK ("checkKey" ~ '^[A-Z][A-Z0-9_]*$');

ALTER TABLE "reports"
  ADD CONSTRAINT "reports_retention_chk"
  CHECK (
    "expiresAt" > "createdAt"
    AND "expiresAt" <= "createdAt" + interval '7 days'
  );

CREATE OR REPLACE FUNCTION enforce_record_immutability()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."createdAt" IS DISTINCT FROM OLD."createdAt" THEN
    RAISE EXCEPTION 'createdAt es inmutable';
  END IF;
  IF TG_TABLE_NAME = 'scans' AND NEW."userId" IS DISTINCT FROM OLD."userId" THEN
    RAISE EXCEPTION 'No se permite reasignar el propietario';
  END IF;
  IF TG_TABLE_NAME = 'findings' AND NEW."scanId" IS DISTINCT FROM OLD."scanId" THEN
    RAISE EXCEPTION 'No se permite reasignar el escaneo';
  END IF;
  IF TG_TABLE_NAME = 'reports' AND (
    NEW."userId" IS DISTINCT FROM OLD."userId"
    OR NEW."scanId" IS DISTINCT FROM OLD."scanId"
    OR NEW."type" IS DISTINCT FROM OLD."type"
  ) THEN
    RAISE EXCEPTION 'No se permite cambiar el propietario, escaneo o tipo';
  END IF;
  IF TG_TABLE_NAME = 'notifications' AND NEW."userId" IS DISTINCT FROM OLD."userId" THEN
    RAISE EXCEPTION 'No se permite reasignar el propietario';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER users_immutable_fields BEFORE UPDATE ON "users"
  FOR EACH ROW EXECUTE FUNCTION enforce_record_immutability();
CREATE TRIGGER scans_immutable_fields BEFORE UPDATE ON "scans"
  FOR EACH ROW EXECUTE FUNCTION enforce_record_immutability();
CREATE TRIGGER findings_immutable_fields BEFORE UPDATE ON "findings"
  FOR EACH ROW EXECUTE FUNCTION enforce_record_immutability();
CREATE TRIGGER reports_immutable_fields BEFORE UPDATE ON "reports"
  FOR EACH ROW EXECUTE FUNCTION enforce_record_immutability();
CREATE TRIGGER notifications_immutable_fields BEFORE UPDATE ON "notifications"
  FOR EACH ROW EXECUTE FUNCTION enforce_record_immutability();

CREATE OR REPLACE FUNCTION protect_audit_logs()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'audit_logs es de solo anexado';
  END IF;
  IF OLD."userId" IS NOT NULL
     AND NEW."userId" IS NULL
     AND NEW."id" = OLD."id"
     AND NEW."action" = OLD."action"
     AND NEW."ipAddress" IS NOT DISTINCT FROM OLD."ipAddress"
     AND NEW."metadata" IS NOT DISTINCT FROM OLD."metadata"
     AND NEW."createdAt" = OLD."createdAt"
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'audit_logs es de solo anexado';
END;
$$;

CREATE TRIGGER audit_logs_append_only
  BEFORE UPDATE OR DELETE ON "audit_logs"
  FOR EACH ROW EXECUTE FUNCTION protect_audit_logs();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user';
    EXECUTE 'REVOKE UPDATE, DELETE ON TABLE "audit_logs" FROM app_user';
    EXECUTE 'REVOKE ALL ON TABLE "_prisma_migrations" FROM app_user';
  END IF;
END $$;
