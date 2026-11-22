CREATE OR REPLACE FUNCTION enforce_report_scan_owner()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."scanId" IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1
      FROM "scans" s
      WHERE s."id" = NEW."scanId"
        AND s."userId" = NEW."userId"
    ) THEN
      RAISE EXCEPTION 'El escaneo no pertenece al usuario del reporte';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER reports_scan_owner_check
  BEFORE INSERT OR UPDATE ON "reports"
  FOR EACH ROW EXECUTE FUNCTION enforce_report_scan_owner();
