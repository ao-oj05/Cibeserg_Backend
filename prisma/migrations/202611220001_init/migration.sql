CREATE TYPE "UserRole" AS ENUM ('USER', 'ADMIN');
CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELED');
CREATE TYPE "RiskLevel" AS ENUM ('SAFE', 'WARNING', 'CRITICAL');
CREATE TYPE "FindingStatus" AS ENUM ('PASSED', 'FAILED');
CREATE TYPE "FindingSeverity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE "ReportType" AS ENUM ('EXECUTIVE', 'TECHNICAL', 'COMPARATIVE');
CREATE TYPE "NotificationType" AS ENUM ('HIGH_RISK_ALERT', 'CERTIFICATE_EXPIRING', 'SCAN_COMPLETED', 'SYSTEM');
CREATE TYPE "AuditAction" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'SCAN_CREATED', 'SCAN_STARTED', 'SCAN_COMPLETED', 'REPORT_GENERATED', 'REPORT_DOWNLOADED');

CREATE TABLE "users" (
  "id" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "passwordHash" TEXT NOT NULL,
  "name" TEXT,
  "role" "UserRole" NOT NULL DEFAULT 'USER',
  "suspendedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

CREATE TABLE "scans" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "targetUrl" TEXT NOT NULL,
  "host" TEXT NOT NULL,
  "ipAddress" TEXT,
  "riskScore" INTEGER NOT NULL DEFAULT 0,
  "riskLevel" "RiskLevel" NOT NULL DEFAULT 'CRITICAL',
  "status" "ScanStatus" NOT NULL DEFAULT 'PENDING',
  "responseTimeMs" INTEGER,
  "httpsRedirect" BOOLEAN NOT NULL DEFAULT false,
  "sslValid" BOOLEAN NOT NULL DEFAULT false,
  "sslIssuer" TEXT,
  "sslDaysLeft" INTEGER,
  "sslProtocol" TEXT,
  "rawHeaders" JSONB,
  "confirmedOwnership" BOOLEAN NOT NULL DEFAULT true,
  "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "scans_userId_host_idx" ON "scans"("userId", "host");
CREATE INDEX "scans_userId_createdAt_idx" ON "scans"("userId", "createdAt");
ALTER TABLE "scans"
  ADD CONSTRAINT "scans_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "findings" (
  "id" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "category" TEXT NOT NULL,
  "checkKey" VARCHAR(50) NOT NULL,
  "title" TEXT NOT NULL,
  "description" TEXT NOT NULL,
  "status" "FindingStatus" NOT NULL,
  "severity" "FindingSeverity" NOT NULL DEFAULT 'INFO',
  "remediation" TEXT,
  "evidence" JSONB,
  "rawData" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "findings_scanId_checkKey_key" ON "findings"("scanId", "checkKey");
CREATE INDEX "findings_scanId_idx" ON "findings"("scanId");
ALTER TABLE "findings"
  ADD CONSTRAINT "findings_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "reports" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "scanId" TEXT,
  "type" "ReportType" NOT NULL DEFAULT 'EXECUTIVE',
  "fileName" TEXT NOT NULL,
  "filePath" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "reports_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "reports_userId_expiresAt_idx" ON "reports"("userId", "expiresAt");
ALTER TABLE "reports"
  ADD CONSTRAINT "reports_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "reports_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "notifications" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "title" TEXT NOT NULL,
  "message" TEXT NOT NULL,
  "type" "NotificationType" NOT NULL DEFAULT 'SYSTEM',
  "isRead" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "notifications_userId_isRead_idx" ON "notifications"("userId", "isRead");
ALTER TABLE "notifications"
  ADD CONSTRAINT "notifications_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "audit_logs" (
  "id" TEXT NOT NULL,
  "userId" TEXT,
  "action" "AuditAction" NOT NULL,
  "ipAddress" TEXT,
  "userAgent" TEXT,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "audit_logs_userId_action_idx" ON "audit_logs"("userId", "action");
CREATE INDEX "audit_logs_createdAt_idx" ON "audit_logs"("createdAt");
ALTER TABLE "audit_logs"
  ADD CONSTRAINT "audit_logs_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
