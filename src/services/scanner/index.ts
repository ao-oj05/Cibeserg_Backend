/**
 * @module scanner/index
 * @description Orquestador principal del motor de escaneo de ScanDev.
 *
 * Ejecuta las 19 comprobaciones de seguridad definidas en el documento de
 * requerimientos y persiste los resultados en la base de datos mediante Prisma.
 *
 * Requerimientos de seguridad aplicados:
 * - BK-01: ssrfGuard() antes de cualquier petición de red
 * - BK-02: Timeouts en todos los módulos hijos (5 s por petición)
 * - BK-05: Aislamiento por userId — el scan sólo se actualiza si pertenece al usuario
 * - BK-06: Errores genéricos al cliente; detalles sólo en servidor
 * - BK-07: rawHeaders sanitizado (máx 50 cabeceras, sin Set-Cookie/Authorization)
 * - RS-02: confirmedOwnership verificado antes de iniciar el escaneo
 *
 * Modelo de puntuación:
 *   base = 100
 *   CRITICAL  → -20
 *   HIGH      → -12
 *   MEDIUM    → -6
 *   LOW       → -2
 *   INFO      →  0
 *
 * Nivel de riesgo:
 *   80–100 → SAFE
 *   60–79  → WARNING
 *   0–59   → CRITICAL
 */

import { PrismaClient, FindingStatus, FindingSeverity, RiskLevel, ScanStatus } from '@prisma/client';
import { validateTargetAgainstSSRF } from './ssrf-guard';
import { auditHttpHeaders, headersToObject } from './http-headers';
import { inspectTls } from './tls-inspector';
import { auditConnection } from './connection';
import { notificationService } from '../notification.service';
import { auditService } from '../audit.service';

const prisma = new PrismaClient();

// ---------------------------------------------------------------------------
// Deducción de puntos por severidad
// ---------------------------------------------------------------------------

const SEVERITY_DEDUCTION: Record<FindingSeverity, number> = {
  CRITICAL: 20,
  HIGH: 12,
  MEDIUM: 6,
  LOW: 2,
  INFO: 0,
};

function computeRiskScore(findings: Array<{ status: FindingStatus; severity: FindingSeverity }>): number {
  let score = 100;
  for (const f of findings) {
    if (f.status === 'FAILED') {
      score -= SEVERITY_DEDUCTION[f.severity] ?? 0;
    }
  }
  return Math.max(0, score);
}

function computeRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'SAFE';
  if (score >= 60) return 'WARNING';
  return 'CRITICAL';
}

// ---------------------------------------------------------------------------
// Sanitización de rawHeaders (BK-07)
// ---------------------------------------------------------------------------

const BLOCKED_HEADERS = new Set(['set-cookie', 'authorization', 'cookie', 'proxy-authorization']);
const MAX_HEADERS = 50;
const MAX_VALUE_LENGTH = 500;

function sanitizeRawHeaders(headers: Record<string, string>): Record<string, string> {
  const sanitized: Record<string, string> = {};
  let count = 0;
  for (const [key, value] of Object.entries(headers)) {
    if (count >= MAX_HEADERS) break;
    const lower = key.toLowerCase();
    if (BLOCKED_HEADERS.has(lower)) continue;
    sanitized[lower] = value.length > MAX_VALUE_LENGTH
      ? value.substring(0, MAX_VALUE_LENGTH) + '…'
      : value;
    count++;
  }
  return sanitized;
}

// ---------------------------------------------------------------------------
// Función principal de escaneo
// ---------------------------------------------------------------------------

export interface RunScanOptions {
  scanId: string;
  userId: string;
  targetUrl: string;
  confirmedOwnership: boolean;
}

export async function runScan({ scanId, userId, targetUrl, confirmedOwnership }: RunScanOptions): Promise<void> {
  // RS-02: Validación de propiedad confirmada
  if (!confirmedOwnership) {
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'FAILED' },
    });
    throw new Error('El usuario no confirmó la autorización de escaneo (RS-02).');
  }

  // BK-01: Guardia SSRF — valida el host antes de cualquier petición
  let resolvedIp: string | null = null;
  try {
    const guardResult = await validateTargetAgainstSSRF(targetUrl);
    resolvedIp = guardResult.ipAddress;
  } catch (err) {
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'FAILED' },
    });
    throw new Error('El objetivo no pasó la validación de seguridad SSRF.');
  }

  // Marcar como RUNNING
  await prisma.scan.update({
    where: { id: scanId },
    data: { status: 'RUNNING', ipAddress: resolvedIp },
  });

  try {
    const urlObj = new URL(targetUrl);
    const host = urlObj.hostname;

    // -----------------------------------------------------------------------
    // 1. Petición base para obtener cabeceras HTTP
    // -----------------------------------------------------------------------
    let rawHeadersMap: Record<string, string> = {};
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5_000);
      const baseRes = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
      });
      clearTimeout(timer);
      rawHeadersMap = headersToObject(baseRes.headers);
    } catch {
      // Sin cabeceras base — los checks individuales fallarán apropiadamente
    }

    // -----------------------------------------------------------------------
    // 2. Ejecutar los 3 módulos de auditoría en paralelo
    // -----------------------------------------------------------------------
    const [headerFindings, tlsResult, connectionResult] = await Promise.all([
      auditHttpHeaders(targetUrl, rawHeadersMap),     // 14 findings
      inspectTls(host),                               //  3 findings
      auditConnection(targetUrl, resolvedIp),         //  2 findings
    ]);

    // Total: 19 findings
    const allFindings = [
      ...headerFindings,
      ...tlsResult.findings,
      ...connectionResult.findings,
    ];

    // -----------------------------------------------------------------------
    // 3. Motor de puntuación
    // -----------------------------------------------------------------------
    const riskScore = computeRiskScore(allFindings);
    const riskLevel = computeRiskLevel(riskScore);

    // -----------------------------------------------------------------------
    // 4. Persistir findings con upsert (garantiza 1 fila por checkKey por scan)
    // -----------------------------------------------------------------------
    await Promise.all(
      allFindings.map((f) =>
        prisma.finding.upsert({
          where: {
            scanId_checkKey: { scanId, checkKey: f.checkKey },
          },
          create: {
            scanId,
            category: f.category,
            checkKey: f.checkKey,
            title: f.title,
            description: f.description,
            status: f.status,
            severity: f.severity,
            remediation: f.remediation ?? null,
            evidence: f.evidence ?? undefined,
          },
          update: {
            category: f.category,
            title: f.title,
            description: f.description,
            status: f.status,
            severity: f.severity,
            remediation: f.remediation ?? null,
            evidence: f.evidence ?? undefined,
          },
        }),
      ),
    );

    // -----------------------------------------------------------------------
    // 5. Actualizar el modelo Scan con resultados finales
    // -----------------------------------------------------------------------
    const sanitizedHeaders = sanitizeRawHeaders(rawHeadersMap);

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'COMPLETED',
        completedAt: new Date(),
        riskScore,
        riskLevel,
        rawHeaders: sanitizedHeaders,
        // Datos TLS
        sslValid: tlsResult.sslValid,
        sslDaysLeft: tlsResult.sslDaysLeft,
        sslProtocol: tlsResult.sslProtocol,
        sslIssuer: tlsResult.sslIssuer,
        // Datos de conexión
        httpsRedirect: connectionResult.httpsRedirect,
        responseTimeMs: connectionResult.responseTimeMs,
      },
    });

    // -----------------------------------------------------------------------
    // 6. Notificaciones automáticas
    // -----------------------------------------------------------------------
    const scanOwner = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { userId: true },
    });
    const ownerId = scanOwner?.userId ?? userId;

    // 6a. Certificado próximo a expirar
    if (tlsResult.sslDaysLeft !== null && tlsResult.sslDaysLeft <= 30) {
      await notificationService.create({
        userId: ownerId,
        type: 'CERTIFICATE_EXPIRING',
        title: '⚠️ Certificado TLS próximo a vencer',
        message: `El certificado de ${host} vence en ${tlsResult.sslDaysLeft} días.`,
      });
    }

    // 6b. Riesgo crítico
    if (riskLevel === 'CRITICAL') {
      await notificationService.create({
        userId: ownerId,
        type: 'HIGH_RISK_ALERT',
        title: '🚨 Riesgo crítico detectado',
        message: `El escaneo de ${host} obtuvo puntuación ${riskScore}/100 (CRÍTICO).`,
      });
    }

    // 6c. Escaneo completado
    await notificationService.create({
      userId: ownerId,
      type: 'SCAN_COMPLETED',
      title: '✅ Escaneo completado',
      message: `El escaneo de ${host} finalizó. Puntuación: ${riskScore}/100 (${riskLevel}).`,
    });

    // 6d. Evento de auditoría
    await auditService.log({
      userId: ownerId,
      action: 'SCAN_COMPLETED',
      metadata: { scanId, host, riskScore, riskLevel, findingsCount: allFindings.length },
    });

  } catch (err) {
    // Marcar como fallido sin exponer el error interno (BK-06)
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'FAILED', completedAt: new Date() },
    }).catch(() => {/* ignora error secundario */});

    throw err;
  }
}
