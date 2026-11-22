/**
 * @module tls-inspector
 * @description Auditoría TLS: 3 comprobaciones (CR-15, CR-16, CR-17).
 *   CR-15 — Validez del certificado (cadena de confianza)
 *   CR-16 — Días hasta expiración con umbrales por severidad
 *   CR-17 — Versión del protocolo TLS (1.2 o 1.3)
 *
 * Seguridad aplicada:
 * - BK-02: Timeout configurable (5 s por defecto)
 * - BK-06: Errores de red → Finding FAILED genérico sin detalles internos
 */

import * as tls from 'tls';
import * as net from 'net';
import { FindingStatus, FindingSeverity } from '@prisma/client';

export interface TlsFinding {
  checkKey: string;
  category: 'TLS_SSL';
  title: string;
  description: string;
  status: FindingStatus;
  severity: FindingSeverity;
  remediation?: string;
  evidence?: Record<string, unknown>;
}

export interface TlsInspectionResult {
  findings: TlsFinding[];
  /** Días restantes hasta expiración (null si no se pudo obtener) */
  sslDaysLeft: number | null;
  /** true si el certificado es válido y de confianza */
  sslValid: boolean;
  /** Protocolo TLS negociado (ej: "TLSv1.3") */
  sslProtocol: string | null;
  /** Emisor del certificado */
  sslIssuer: string | null;
}

const CONNECT_TIMEOUT_MS = 5_000;
const SAFE_PROTOCOLS = new Set(['TLSv1.2', 'TLSv1.3']);

/**
 * Conecta al host:443 con TLS y obtiene información del certificado.
 * Lanza error si el tiempo de conexión supera CONNECT_TIMEOUT_MS.
 */
function inspectTlsCert(host: string, ipAddress: string, signal?: AbortSignal): Promise<{
  valid: boolean;
  daysLeft: number;
  protocol: string;
  issuer: string;
  subject: string;
  validTo: string;
}> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    };
    const abort = () => {
      socket.destroy(new Error('TLS_ABORTED'));
    };
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('TLS_TIMEOUT'));
    }, CONNECT_TIMEOUT_MS);

    const socket = tls.connect(
      {
        host: ipAddress,
        port: 443,
        servername: net.isIP(host) ? undefined : host,
        // Permitimos auto-verificación; si falla → valid = false
        rejectUnauthorized: false,
      },
      () => {
        cleanup();

        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol() ?? 'unknown';

        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          reject(new Error('NO_CERT'));
          return;
        }

        // Validez: authorized indica si la cadena es de confianza (CA raíz válida)
        const valid = socket.authorized === true;

        // Fecha de expiración
        const validToDate = new Date(cert.valid_to);
        const now = new Date();
        const daysLeft = Math.floor(
          (validToDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
        );

        // Emisor
        const issuer = cert.issuer
          ? Object.entries(cert.issuer)
              .map(([k, v]) => `${k}=${v}`)
              .join(', ')
          : 'Desconocido';

        // Sujeto
        const subject = typeof cert.subject?.CN === 'string' ? cert.subject.CN : host;
        const validTo = typeof cert.valid_to === 'string' ? cert.valid_to : '';

        socket.destroy();
        resolve({ valid, daysLeft, protocol, issuer, subject, validTo });
      },
    );

    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();

    socket.on('error', (err) => {
      cleanup();
      socket.destroy();
      reject(err);
    });
  });
}

// ---------------------------------------------------------------------------
// Checks individuales
// ---------------------------------------------------------------------------

function buildCertValidFinding(valid: boolean, errorMsg?: string): TlsFinding {
  if (!valid || errorMsg) {
    return {
      checkKey: 'TLS_CERT_VALID',
      category: 'TLS_SSL',
      title: 'Certificado TLS no válido o no confiable',
      description: errorMsg
        ? `No se pudo verificar el certificado: ${errorMsg}`
        : 'El certificado no está firmado por una CA de confianza o está autofirmado.',
      status: 'FAILED',
      severity: 'CRITICAL',
      remediation:
        'Instala un certificado válido de una CA de confianza (ej: Let\'s Encrypt, DigiCert). Nunca uses certificados autofirmados en producción.',
      evidence: { valid, error: errorMsg ?? null },
    };
  }
  return {
    checkKey: 'TLS_CERT_VALID',
    category: 'TLS_SSL',
    title: 'Certificado TLS válido y confiable',
    description: 'El certificado está firmado por una CA de confianza y la cadena es válida.',
    status: 'PASSED',
    severity: 'INFO',
    evidence: { valid },
  };
}

function buildCertExpiryFinding(
  daysLeft: number,
  validTo: string,
  issuer: string,
): TlsFinding {
  if (daysLeft <= 0) {
    return {
      checkKey: 'TLS_CERT_EXPIRY',
      category: 'TLS_SSL',
      title: 'Certificado TLS expirado',
      description: `El certificado expiró hace ${Math.abs(daysLeft)} días (${validTo}).`,
      status: 'FAILED',
      severity: 'CRITICAL',
      remediation: 'Renueva el certificado de inmediato.',
      evidence: { daysLeft, validTo, issuer },
    };
  }
  if (daysLeft <= 7) {
    return {
      checkKey: 'TLS_CERT_EXPIRY',
      category: 'TLS_SSL',
      title: 'Certificado TLS expira en ≤7 días (CRÍTICO)',
      description: `El certificado expirará en ${daysLeft} día(s) (${validTo}). Riesgo inmediato de interrupción.`,
      status: 'FAILED',
      severity: 'HIGH',
      remediation: 'Renueva el certificado de forma urgente antes de que expire.',
      evidence: { daysLeft, validTo, issuer },
    };
  }
  if (daysLeft <= 30) {
    return {
      checkKey: 'TLS_CERT_EXPIRY',
      category: 'TLS_SSL',
      title: 'Certificado TLS expira en ≤30 días',
      description: `El certificado expirará en ${daysLeft} días (${validTo}).`,
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: 'Programa la renovación del certificado en los próximos días.',
      evidence: { daysLeft, validTo, issuer },
    };
  }
  return {
    checkKey: 'TLS_CERT_EXPIRY',
    category: 'TLS_SSL',
    title: 'Certificado TLS con vigencia suficiente',
    description: `El certificado tiene ${daysLeft} días de vigencia restante (expira ${validTo}).`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { daysLeft, validTo, issuer },
  };
}

function buildProtocolFinding(protocol: string): TlsFinding {
  if (!SAFE_PROTOCOLS.has(protocol)) {
    return {
      checkKey: 'TLS_PROTOCOL',
      category: 'TLS_SSL',
      title: 'Protocolo TLS obsoleto o inseguro',
      description: `Se negoció el protocolo '${protocol}'. Solo TLS 1.2 y 1.3 son seguros.`,
      status: 'FAILED',
      severity: 'HIGH',
      remediation:
        'Desactiva TLS 1.0 y TLS 1.1 en la configuración del servidor web. Habilita únicamente TLS 1.2 y 1.3.',
      evidence: { protocol },
    };
  }
  return {
    checkKey: 'TLS_PROTOCOL',
    category: 'TLS_SSL',
    title: `Protocolo TLS seguro (${protocol})`,
    description: `Se usa ${protocol}, que es un protocolo TLS seguro y moderno.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { protocol },
  };
}

// ---------------------------------------------------------------------------
// Función principal exportada
// ---------------------------------------------------------------------------

/**
 * Inspecciona TLS del host en el puerto 443.
 * Devuelve exactamente 3 findings (TLS_CERT_VALID, TLS_CERT_EXPIRY, TLS_PROTOCOL)
 * más los metadatos del certificado para guardar en el modelo Scan.
 *
 * @param host  Nombre de host sin esquema (ej: "example.com")
 */
export async function inspectTls(
  host: string,
  ipAddress: string,
  signal?: AbortSignal,
): Promise<TlsInspectionResult> {
  try {
    const { valid, daysLeft, protocol, issuer, validTo } = await inspectTlsCert(
      host,
      ipAddress,
      signal,
    );

    return {
      sslValid: valid,
      sslDaysLeft: daysLeft,
      sslProtocol: protocol,
      sslIssuer: issuer,
      findings: [
        buildCertValidFinding(valid),
        buildCertExpiryFinding(daysLeft, validTo, issuer),
        buildProtocolFinding(protocol),
      ],
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Error desconocido';
    // No exponemos el error interno (BK-06); sólo indicamos que falló
    const genericError =
      message === 'TLS_TIMEOUT'
        ? 'Tiempo de conexión TLS agotado (>5 s).'
        : 'No se pudo establecer una conexión TLS con el servidor.';

    return {
      sslValid: false,
      sslDaysLeft: null,
      sslProtocol: null,
      sslIssuer: null,
      findings: [
        buildCertValidFinding(false, genericError),
        {
          checkKey: 'TLS_CERT_EXPIRY',
          category: 'TLS_SSL',
          title: 'No se pudo verificar expiración del certificado',
          description: genericError,
          status: 'FAILED',
          severity: 'CRITICAL',
          remediation: 'Verifica que el servidor sea accesible en el puerto 443.',
          evidence: { error: genericError },
        },
        {
          checkKey: 'TLS_PROTOCOL',
          category: 'TLS_SSL',
          title: 'No se pudo verificar protocolo TLS',
          description: genericError,
          status: 'FAILED',
          severity: 'HIGH',
          remediation: 'Verifica que el servidor sea accesible en el puerto 443.',
          evidence: { error: genericError },
        },
      ],
    };
  }
}
