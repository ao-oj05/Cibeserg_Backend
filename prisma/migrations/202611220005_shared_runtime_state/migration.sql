CREATE TYPE "ScanJobStatus" AS ENUM ('PENDING', 'RUNNING');

CREATE TABLE "scan_jobs" (
  "id" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "status" "ScanJobStatus" NOT NULL DEFAULT 'PENDING',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "lockedAt" TIMESTAMP(3),
  CONSTRAINT "scan_jobs_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "scan_jobs_scanId_fkey"
    FOREIGN KEY ("scanId") REFERENCES "scans"("id")
    ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "scan_jobs_scanId_key" ON "scan_jobs"("scanId");
CREATE INDEX "scan_jobs_status_createdAt_idx" ON "scan_jobs"("status", "createdAt");

INSERT INTO "scan_jobs" ("id", "scanId", "status", "createdAt", "updatedAt", "lockedAt")
SELECT
  gen_random_uuid()::text,
  "id",
  CASE WHEN "status" = 'RUNNING' THEN 'RUNNING'::"ScanJobStatus"
       ELSE 'PENDING'::"ScanJobStatus"
  END,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP,
  CASE WHEN "status" = 'RUNNING' THEN CURRENT_TIMESTAMP ELSE NULL END
FROM "scans"
WHERE "status" IN ('PENDING', 'RUNNING');

CREATE TABLE "rate_limit_hits" (
  "id" TEXT NOT NULL,
  "keyDigest" VARCHAR(64) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "rate_limit_hits_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "rate_limit_hits_keyDigest_createdAt_idx"
  ON "rate_limit_hits"("keyDigest", "createdAt");
CREATE INDEX "rate_limit_hits_createdAt_idx"
  ON "rate_limit_hits"("createdAt");

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "scan_jobs" TO app_user';
    EXECUTE 'GRANT SELECT, INSERT, DELETE ON TABLE "rate_limit_hits" TO app_user';
  END IF;
END $$;
