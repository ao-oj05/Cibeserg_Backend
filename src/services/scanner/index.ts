import { prisma } from "@/lib/db";
import { validateTargetAgainstSSRF } from "./ssrf-guard";
import { auditHttpHeaders } from "./http-headers";
import { inspectTLS } from "./tls-inspector";
import { auditConnection } from "./connection";
import { FindingSeverity, FindingStatus } from "@prisma/client";

// Rule score weights (Sum = 100)
const RULE_WEIGHTS: Record<string, number> = {
  HSTS: 15,
  CSP: 15,
  X_FRAME_OPTIONS: 10,
  X_CONTENT_TYPE_OPTIONS: 8,
  REFERRER_POLICY: 5,
  PERMISSIONS_POLICY: 4,
  X_PERMITTED_CROSS_DOMAIN_POLICIES: 3,
  SSL_VALIDITY: 15,
  SSL_EXPIRATION: 5,
  TLS_PROTOCOL: 10,
  HTTPS_REDIRECT: 7,
  RESPONSE_TIME: 3,
};

export interface ScanExecutionParams {
  userId: string;
  targetUrl: string;
}

/**
 * Main Orchestrator for ScanDev Security Audit
 */
export async function executeSecurityScan({ userId, targetUrl }: ScanExecutionParams) {
  // 1. SSRF Guard Check (Sequential)
  const { host, ipAddress, normalizedUrl } = await validateTargetAgainstSSRF(targetUrl);

  // 2. Initialize Scan Record in DB (Status: RUNNING)
  const initialScan = await prisma.scan.create({
    data: {
      userId,
      targetUrl: normalizedUrl,
      host,
      ipAddress,
      status: "RUNNING",
      riskScore: 0,
    },
  });

  try {
    // 3. Parallel Execution of Audits
    const [headerResult, tlsResult, connectionResult] = await Promise.all([
      auditHttpHeaders(normalizedUrl).catch((err) => ({
        statusCode: 0,
        rawHeaders: {},
        findings: [
          {
            ruleKey: "HTTP_ERROR",
            category: "HTTP_HEADERS" as const,
            title: "Fallo en consulta de cabeceras",
            description: err instanceof Error ? err.message : String(err),
            status: "FAILED" as const,
            severity: "HIGH" as const,
          },
        ],
      })),
      inspectTLS(host),
      auditConnection(host, normalizedUrl),
    ]);

    // 4. Combine all findings
    const allFindings = [
      ...headerResult.findings,
      ...tlsResult.findings,
      ...connectionResult.findings,
    ];

    // 5. Calculate Risk Score (0 - 100)
    let score = 0;
    for (const finding of allFindings) {
      if (finding.status === "PASSED") {
        const weight = RULE_WEIGHTS[finding.ruleKey] || 0;
        score += weight;
      }
    }
    // Clamp score strictly between 0 and 100
    const riskScore = Math.min(100, Math.max(0, score));

    // 6. Update Scan with metrics and COMPLETED status
    const completedScan = await prisma.scan.update({
      where: { id: initialScan.id },
      data: {
        status: "COMPLETED",
        riskScore,
        responseTimeMs: connectionResult.responseTimeMs,
        httpsRedirect: connectionResult.httpsRedirect,
        sslValid: tlsResult.sslValid,
        sslIssuer: tlsResult.sslIssuer,
        sslDaysLeft: tlsResult.sslDaysLeft,
        sslProtocol: tlsResult.sslProtocol,
        completedAt: new Date(),
        findings: {
          create: allFindings.map((f) => ({
            category: f.category,
            ruleKey: f.ruleKey,
            title: f.title,
            description: f.description,
            status: f.status as FindingStatus,
            severity: f.severity as FindingSeverity,
            remediation: f.remediation,
            rawData: f.rawData ? JSON.parse(JSON.stringify(f.rawData)) : undefined,
          })),
        },
      },
      include: {
        findings: true,
      },
    });

    // 7. Automated Security Notifications Trigger
    if (riskScore < 60) {
      await prisma.notification.create({
        data: {
          userId,
          title: "Alerta de Riesgo Alto de Seguridad",
          message: `El escaneo para ${host} ha arrojado una calificación crítica de ${riskScore}/100. Se detectaron múltiples directivas de seguridad vulnerables.`,
          type: "HIGH_RISK_ALERT",
        },
      });
    }

    if (tlsResult.sslDaysLeft !== null && tlsResult.sslDaysLeft <= 15) {
      await prisma.notification.create({
        data: {
          userId,
          title: "Certificado SSL Próximo a Expirar",
          message: `El certificado SSL/TLS de ${host} expira en ${tlsResult.sslDaysLeft} días. Renueve su certificado para evitar caídas de servicio.`,
          type: "CERTIFICATE_EXPIRING",
        },
      });
    }

    return completedScan;
  } catch (err: unknown) {
    // If orchestrator fails after scan creation, mark scan as FAILED
    await prisma.scan.update({
      where: { id: initialScan.id },
      data: {
        status: "FAILED",
        completedAt: new Date(),
      },
    });

    throw err;
  }
}
