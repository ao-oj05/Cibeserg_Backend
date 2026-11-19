/**
 * @module connection
 * @description Auditoría de conexión: 2 comprobaciones (CR-18, CR-19).
 *   CR-18 — Redirección HTTP → HTTPS
 *   CR-19 — Disponibilidad: sin respuestas 5xx y tiempo ≤ 3 s
 *
 * Seguridad aplicada:
 * - BK-01: La URL ya fue validada por ssrfGuard() en el orquestador
 * - BK-02: Timeout estricto de 5 s por petición
 * - BK-06: Errores internos no se exponen en el mensaje del Finding
 */

import { FindingStatus, FindingSeverity } from '@prisma/client';

export interface ConnectionFinding {
  checkKey: string;
  category: 'CONNECTION';
  title: string;
  description: string;
  status: FindingStatus;
  severity: FindingSeverity;
  remediation?: string;
  evidence?: Record<string, unknown>;
}

export interface ConnectionResult {
  findings: ConnectionFinding[];
  /** true si el servidor redirige HTTP → HTTPS */
  httpsRedirect: boolean;
  /** Tiempo de respuesta en ms (null si no se pudo medir) */
  responseTimeMs: number | null;
  /** IP del servidor obtenida del DNS (guardada en scan) */
  ipAddress: string | null;
}

const REQUEST_TIMEOUT_MS = 5_000;
/** Umbral máximo de tiempo de respuesta aceptable */
const MAX_RESPONSE_TIME_MS = 3_000;

/**
 * Realiza una petición GET con timeout.
 * Devuelve { status, url, responseTimeMs } tras seguir redirecciones.
 */
async function timedFetch(
  url: string,
  options: RequestInit = {},
): Promise<{ status: number; finalUrl: string; responseTimeMs: number }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const start = Date.now();
  try {
    const res = await fetch(url, { ...options, signal: controller.signal, redirect: 'follow' });
    const responseTimeMs = Date.now() - start;
    return { status: res.status, finalUrl: res.url, responseTimeMs };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// CR-18: Redirección HTTP → HTTPS
// ---------------------------------------------------------------------------

async function checkHttpsRedirect(targetUrl: string): Promise<ConnectionFinding & { redirected: boolean }> {
  const checkKey = 'HTTPS_REDIRECT';
  let redirected = false;

  try {
    const urlObj = new URL(targetUrl);
    // Siempre probamos la versión HTTP del mismo host
    const httpUrl = `http://${urlObj.host}${urlObj.pathname}${urlObj.search}`;

    const { finalUrl } = await timedFetch(httpUrl, { redirect: 'follow' });
    redirected = finalUrl.startsWith('https://');

    if (!redirected) {
      return {
        checkKey,
        category: 'CONNECTION',
        title: 'Sin redirección HTTP → HTTPS',
        description: `La URL HTTP '${httpUrl}' no redirigió a HTTPS. URL final: '${finalUrl}'`,
        status: 'FAILED',
        severity: 'HIGH',
        remediation:
          'Configura una redirección 301 permanente de HTTP a HTTPS en el servidor web o balanceador de carga.',
        evidence: { httpUrl, finalUrl, redirected: false },
        redirected: false,
      };
    }

    return {
      checkKey,
      category: 'CONNECTION',
      title: 'Redirección HTTP → HTTPS activa',
      description: `La petición HTTP fue redirigida correctamente a HTTPS.`,
      status: 'PASSED',
      severity: 'INFO',
      evidence: { httpUrl, finalUrl, redirected: true },
      redirected: true,
    };
  } catch {
    // Error de red o timeout — tratamos como fallo (no hay redirección verificada)
    return {
      checkKey,
      category: 'CONNECTION',
      title: 'No se pudo verificar la redirección HTTP → HTTPS',
      description: 'No se recibió respuesta desde la URL HTTP en el tiempo límite.',
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: 'Verifica que el servidor responda en el puerto 80 y redirija a HTTPS.',
      evidence: { redirected: false, error: 'Timeout o sin respuesta' },
      redirected: false,
    };
  }
}

// ---------------------------------------------------------------------------
// CR-19: Disponibilidad
// ---------------------------------------------------------------------------

async function checkAvailability(targetUrl: string): Promise<ConnectionFinding & { responseTimeMs: number | null }> {
  const checkKey = 'AVAILABILITY';

  try {
    const { status, responseTimeMs } = await timedFetch(targetUrl);

    if (status >= 500 && status < 600) {
      return {
        checkKey,
        category: 'CONNECTION',
        title: 'El servidor respondió con error 5xx',
        description: `El servidor devolvió HTTP ${status}, lo que indica un error interno del servidor.`,
        status: 'FAILED',
        severity: 'HIGH',
        remediation:
          'Revisa los logs del servidor web y la aplicación para identificar la causa del error 5xx.',
        evidence: { httpStatus: status, responseTimeMs },
        responseTimeMs,
      };
    }

    if (responseTimeMs > MAX_RESPONSE_TIME_MS) {
      return {
        checkKey,
        category: 'CONNECTION',
        title: 'Tiempo de respuesta superior a 3 s',
        description: `El servidor tardó ${responseTimeMs} ms en responder, superando el límite de ${MAX_RESPONSE_TIME_MS} ms.`,
        status: 'FAILED',
        severity: 'MEDIUM',
        remediation:
          'Optimiza el rendimiento del servidor: revisa caché, CDN, consultas de base de datos y recursos del servidor.',
        evidence: { httpStatus: status, responseTimeMs, limitMs: MAX_RESPONSE_TIME_MS },
        responseTimeMs,
      };
    }

    return {
      checkKey,
      category: 'CONNECTION',
      title: 'Servidor disponible y responde rápidamente',
      description: `El servidor respondió con HTTP ${status} en ${responseTimeMs} ms (límite: ${MAX_RESPONSE_TIME_MS} ms).`,
      status: 'PASSED',
      severity: 'INFO',
      evidence: { httpStatus: status, responseTimeMs, limitMs: MAX_RESPONSE_TIME_MS },
      responseTimeMs,
    };
  } catch {
    return {
      checkKey,
      category: 'CONNECTION',
      title: 'Servidor no disponible o sin respuesta',
      description: 'No se recibió respuesta del servidor dentro del tiempo límite de 5 s.',
      status: 'FAILED',
      severity: 'HIGH',
      remediation: 'Verifica que el servidor esté en línea y responda en el puerto 443.',
      evidence: { error: 'Timeout o conexión rechazada', limitMs: MAX_RESPONSE_TIME_MS },
      responseTimeMs: null,
    };
  }
}

// ---------------------------------------------------------------------------
// Función principal exportada
// ---------------------------------------------------------------------------

/**
 * Audita disponibilidad y redirección HTTPS del objetivo.
 * Devuelve exactamente 2 findings (HTTPS_REDIRECT, AVAILABILITY).
 *
 * @param targetUrl  URL completa validada por ssrfGuard
 * @param ipAddress  IP resuelta (opcional, se guarda en evidencia)
 */
export async function auditConnection(
  targetUrl: string,
  ipAddress?: string | null,
): Promise<ConnectionResult> {
  const [redirectResult, availabilityResult] = await Promise.all([
    checkHttpsRedirect(targetUrl),
    checkAvailability(targetUrl),
  ]);

  // Extraemos los campos extra antes de construir los findings limpios
  const { redirected, ...redirectFinding } = redirectResult;
  const { responseTimeMs, ...availabilityFinding } = availabilityResult;

  return {
    httpsRedirect: redirected,
    responseTimeMs: responseTimeMs,
    ipAddress: ipAddress ?? null,
    findings: [redirectFinding, availabilityFinding],
  };
}
