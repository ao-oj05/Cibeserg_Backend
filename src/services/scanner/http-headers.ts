/**
 * @module http-headers
 * @description Auditoría de 14 cabeceras HTTP de seguridad (CR-01 a CR-08, CORS×4, CR-09 a CR-14).
 *
 * Seguridad aplicada:
 * - BK-01: Sin SSRF — todas las peticiones pasan por ssrfGuard() antes de ejecutarse
 * - BK-02: Timeout de 5 s en cada fetch; AbortController con señal
 * - BK-06: Los errores de red no revelan detalles internos en el Finding público
 */

import { FindingStatus, FindingSeverity } from '@prisma/client';
import { safeHttpRequest } from './safe-http';

export interface HeaderFinding {
  checkKey: string;
  category: 'HTTP_HEADERS';
  title: string;
  description: string;
  status: FindingStatus;
  severity: FindingSeverity;
  remediation?: string;
  evidence?: Record<string, unknown>;
}

/** Resultado de un probe CORS individual */
interface CorsProbe {
  label: string;
  originSent: string | null;
  method: string;
  acao: string | null;
  acac: string | null;        // Access-Control-Allow-Credentials
  acam: string | null;        // Access-Control-Allow-Methods (OPTIONS)
  reflected: boolean;
  credentialsExposed: boolean;
}

/**
 * Convierte los headers de una Response a un objeto plano para evidencia.
 * Excluye Set-Cookie y Authorization por seguridad (BK-07).
 */
function headersToObject(headers: Headers): Record<string, string> {
  const obj: Record<string, string> = {};
  headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (lower === 'set-cookie' || lower === 'authorization') return;
    obj[lower] = value;
  });
  return obj;
}

// ---------------------------------------------------------------------------
// Checks individuales
// ---------------------------------------------------------------------------

function checkCSP(value: string | null): HeaderFinding {
  const checkKey = 'CSP';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Content-Security-Policy ausente',
      description: 'La cabecera Content-Security-Policy no está presente.',
      status: 'FAILED',
      severity: 'HIGH',
      remediation:
        "Añade CSP con directivas restrictivas. Evita 'unsafe-inline' y 'unsafe-eval'.",
      evidence: { header: null },
    };
  }
  const lower = value.toLowerCase();
  if (lower.includes('unsafe-inline') || lower.includes('unsafe-eval')) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Content-Security-Policy insegura',
      description:
        "CSP contiene 'unsafe-inline' o 'unsafe-eval', lo que permite ejecución de scripts arbitrarios.",
      status: 'FAILED',
      severity: 'HIGH',
      remediation: "Elimina 'unsafe-inline' y 'unsafe-eval' de la directiva CSP.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Content-Security-Policy correcta',
    description: 'CSP presente y sin directivas inseguras.',
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkHSTS(value: string | null): HeaderFinding {
  const checkKey = 'HSTS';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Strict-Transport-Security ausente',
      description: 'La cabecera HSTS no está presente.',
      status: 'FAILED',
      severity: 'HIGH',
      remediation:
        'Añade Strict-Transport-Security con max-age >= 31536000 e includeSubDomains.',
      evidence: { header: null },
    };
  }
  const match = value.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = match ? parseInt(match[1], 10) : 0;
  if (maxAge < 31_536_000) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Strict-Transport-Security con max-age insuficiente',
      description: `HSTS presente pero max-age=${maxAge} es menor al mínimo recomendado (31536000).`,
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: 'Establece max-age a 31536000 (1 año) o superior.',
      evidence: { header: value, maxAge },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Strict-Transport-Security correcta',
    description: `HSTS presente con max-age=${maxAge}.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value, maxAge },
  };
}

function checkXFrameOptions(value: string | null): HeaderFinding {
  const checkKey = 'X_FRAME_OPTIONS';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'X-Frame-Options ausente',
      description: 'Sin X-Frame-Options el sitio es vulnerable a Clickjacking.',
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: "Añade X-Frame-Options: DENY o SAMEORIGIN.",
      evidence: { header: null },
    };
  }
  const upper = value.toUpperCase().trim();
  if (upper !== 'DENY' && upper !== 'SAMEORIGIN') {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'X-Frame-Options con valor no recomendado',
      description: `Valor '${value}' no es DENY ni SAMEORIGIN.`,
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: "Establece X-Frame-Options: DENY o SAMEORIGIN.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'X-Frame-Options correcta',
    description: `X-Frame-Options establecida a '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkXContentTypeOptions(value: string | null): HeaderFinding {
  const checkKey = 'X_CONTENT_TYPE_OPTIONS';
  if (!value || value.toLowerCase().trim() !== 'nosniff') {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'X-Content-Type-Options ausente o incorrecta',
      description: 'Sin nosniff el navegador puede interpretar tipos MIME de forma insegura.',
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Añade X-Content-Type-Options: nosniff.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'X-Content-Type-Options correcta',
    description: "X-Content-Type-Options establecida a 'nosniff'.",
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkReferrerPolicy(value: string | null): HeaderFinding {
  const checkKey = 'REFERRER_POLICY';
  const safeValues = new Set([
    'no-referrer',
    'no-referrer-when-downgrade',
    'strict-origin',
    'strict-origin-when-cross-origin',
  ]);
  if (!value || !safeValues.has(value.toLowerCase().trim())) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Referrer-Policy ausente o débil',
      description: `Valor '${value ?? 'ausente'}' no es suficientemente restrictivo.`,
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Establece Referrer-Policy: strict-origin-when-cross-origin o más estricto.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Referrer-Policy correcta',
    description: `Referrer-Policy establecida a '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkPermissionsPolicy(value: string | null): HeaderFinding {
  const checkKey = 'PERMISSIONS_POLICY';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Permissions-Policy ausente',
      description: 'Sin Permissions-Policy el navegador puede exponer APIs sensibles.',
      status: 'FAILED',
      severity: 'LOW',
      remediation:
        "Añade Permissions-Policy restringiendo funciones innecesarias (camera=(), microphone=(), geolocation=(), etc.).",
      evidence: { header: null },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Permissions-Policy presente',
    description: `Permissions-Policy configurada.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkXPermittedCrossDomainPolicies(value: string | null): HeaderFinding {
  const checkKey = 'X_PERMITTED_CROSS_DOMAIN';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'X-Permitted-Cross-Domain-Policies ausente',
      description: 'Falta la cabecera de control de políticas cross-domain para Adobe Flash/Acrobat.',
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Añade X-Permitted-Cross-Domain-Policies: none.",
      evidence: { header: null },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'X-Permitted-Cross-Domain-Policies presente',
    description: `Valor: '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

/**
 * CR-08: CORS — 4 sondas activas
 * S1: Origin propio (base)
 * S2: Origin falso `https://scandev-prueba.invalid`
 * S3: Origin `null`
 * S4: Preflight OPTIONS con Origin falso
 */
async function checkCORS(targetUrl: string, signal?: AbortSignal): Promise<HeaderFinding> {
  const checkKey = 'CORS';
  const probes: CorsProbe[] = [];
  let failed = false;
  let maxSeverity: FindingSeverity = 'INFO';
  const issues: string[] = [];

  const urlObj = new URL(targetUrl);
  const ownOrigin = urlObj.origin;

  const probeConfigs: Array<{ label: string; origin: string | null; method: string }> = [
    { label: 'S1_own_origin', origin: ownOrigin, method: 'GET' },
    { label: 'S2_fake_origin', origin: 'https://scandev-prueba.invalid', method: 'GET' },
    { label: 'S3_null_origin', origin: 'null', method: 'GET' },
    { label: 'S4_preflight', origin: 'https://scandev-prueba.invalid', method: 'OPTIONS' },
  ];

  for (const cfg of probeConfigs) {
    const headers: HeadersInit = {
      'Accept': 'text/html,application/xhtml+xml,*/*',
    };
    (headers as Record<string, string>)['Origin'] = cfg.origin ?? 'null';
    if (cfg.method === 'OPTIONS') {
      (headers as Record<string, string>)['Access-Control-Request-Method'] = 'GET';
      (headers as Record<string, string>)['Access-Control-Request-Headers'] = 'x-custom-header';
    }

    let acao: string | null = null;
    let acac: string | null = null;
    let acam: string | null = null;

    try {
      const res = await safeHttpRequest(targetUrl, {
        method: cfg.method,
        headers,
        signal,
      });
      acao = res.headers.get('access-control-allow-origin');
      acac = res.headers.get('access-control-allow-credentials');
      acam = res.headers.get('access-control-allow-methods');
    } catch {
      // Timeout o error de red — la sonda no pudo completarse
    }

    const reflected =
      acao !== null &&
      (acao === cfg.origin || acao === '*');

    const credentialsExposed =
      reflected &&
      acac?.toLowerCase() === 'true' &&
      acao !== '*';

    // Detectar problema: origen falso o null reflejado
    if (
      (cfg.label === 'S2_fake_origin' || cfg.label === 'S3_null_origin' || cfg.label === 'S4_preflight') &&
      reflected
    ) {
      failed = true;
      const sev: FindingSeverity = credentialsExposed ? 'CRITICAL' : 'HIGH';
      if (sev === 'CRITICAL') maxSeverity = 'CRITICAL';
      else if (maxSeverity !== 'CRITICAL') maxSeverity = 'HIGH';

      issues.push(
        `${cfg.label}: ACAO='${acao}'${credentialsExposed ? ', credentials=true (CRÍTICO)' : ''}`,
      );
    }

    probes.push({ label: cfg.label, originSent: cfg.origin, method: cfg.method, acao, acac, acam, reflected, credentialsExposed });
  }

  if (failed) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Política CORS permisiva detectada',
      description: `El servidor refleja orígenes arbitrarios en Access-Control-Allow-Origin. Problemas: ${issues.join('; ')}`,
      status: 'FAILED',
      severity: maxSeverity,
      remediation:
        'Restringe ACAO a orígenes explícitamente permitidos. Nunca uses ACAO: * con credenciales. Rechaza el origen null.',
      evidence: { probes },
    };
  }

  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Política CORS correcta',
    description: 'El servidor no refleja orígenes arbitrarios en CORS.',
    status: 'PASSED',
    severity: 'INFO',
    evidence: { probes },
  };
}

function checkCacheControl(value: string | null): HeaderFinding {
  const checkKey = 'CACHE_CONTROL';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cache-Control ausente',
      description: 'Sin Cache-Control el navegador puede cachear contenido sensible.',
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: "Añade Cache-Control: no-store, no-cache, must-revalidate para rutas autenticadas.",
      evidence: { header: null },
    };
  }
  if (value.toLowerCase().includes('public')) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cache-Control con directiva public',
      description: "La directiva 'public' permite que proxies intermedios cacheen respuestas posiblemente sensibles.",
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: "Reemplaza 'public' por 'private, no-store' o 'no-cache' para contenido autenticado.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Cache-Control correcta',
    description: `Cache-Control configurada: '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkCORP(value: string | null): HeaderFinding {
  const checkKey = 'CORP';
  const valid = new Set(['same-origin', 'same-site', 'cross-origin']);
  const recommended = new Set(['same-origin', 'same-site']);
  if (!value || !valid.has(value.toLowerCase().trim())) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cross-Origin-Resource-Policy ausente o incorrecta',
      description: `Valor '${value ?? 'ausente'}' no es válido para CORP.`,
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Añade Cross-Origin-Resource-Policy: same-origin o same-site.",
      evidence: { header: value },
    };
  }
  if (!recommended.has(value.toLowerCase().trim())) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cross-Origin-Resource-Policy con valor permisivo',
      description: "CORP establecida a 'cross-origin', lo que permite cargar recursos desde cualquier origen.",
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Cambia a same-origin o same-site para mayor restricción.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Cross-Origin-Resource-Policy correcta',
    description: `CORP establecida a '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkCOOP(value: string | null): HeaderFinding {
  const checkKey = 'COOP';
  const valid = new Set(['same-origin', 'same-origin-allow-popups', 'unsafe-none']);
  const recommended = new Set(['same-origin', 'same-origin-allow-popups']);
  if (!value || !valid.has(value.toLowerCase().trim())) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cross-Origin-Opener-Policy ausente o incorrecta',
      description: `Valor '${value ?? 'ausente'}' — sin COOP el contexto de navegación puede ser comprometido.`,
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: "Añade Cross-Origin-Opener-Policy: same-origin.",
      evidence: { header: value },
    };
  }
  if (!recommended.has(value.toLowerCase().trim())) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cross-Origin-Opener-Policy débil',
      description: "COOP establecida a 'unsafe-none', lo que no protege el contexto del navegador.",
      status: 'FAILED',
      severity: 'MEDIUM',
      remediation: "Cambia a same-origin o same-origin-allow-popups.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Cross-Origin-Opener-Policy correcta',
    description: `COOP establecida a '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkCOEP(value: string | null): HeaderFinding {
  const checkKey = 'COEP';
  const recommended = new Set(['require-corp', 'credentialless']);
  if (!value || !recommended.has(value.toLowerCase().trim())) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cross-Origin-Embedder-Policy ausente o incorrecta',
      description: `Valor '${value ?? 'ausente'}' — sin COEP el aislamiento cross-origin no está activo.`,
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Añade Cross-Origin-Embedder-Policy: require-corp o credentialless.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Cross-Origin-Embedder-Policy correcta',
    description: `COEP establecida a '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

function checkContentType(value: string | null): HeaderFinding {
  const checkKey = 'CONTENT_TYPE';
  if (!value) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Content-Type ausente',
      description: 'Sin Content-Type el navegador puede realizar sniffing de tipo MIME.',
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Establece Content-Type: text/html; charset=UTF-8 en respuestas HTML.",
      evidence: { header: null },
    };
  }
  // Para HTML esperamos charset=utf-8
  const lower = value.toLowerCase();
  if (lower.includes('text/html') && !lower.includes('charset=utf-8') && !lower.includes('charset=utf8')) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Content-Type HTML sin charset=UTF-8',
      description: "La respuesta HTML no especifica charset=UTF-8, lo que puede exponer a ataques de codificación.",
      status: 'FAILED',
      severity: 'LOW',
      remediation: "Establece Content-Type: text/html; charset=UTF-8.",
      evidence: { header: value },
    };
  }
  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'Content-Type correcta',
    description: `Content-Type: '${value}'.`,
    status: 'PASSED',
    severity: 'INFO',
    evidence: { header: value },
  };
}

/**
 * CR-14: Server / X-Powered-By
 * PASS si están ausentes u ocultos (no revelan versión de software).
 * FAIL si contienen nombre de software con versión.
 */
function checkServerDisclosure(
  serverHeader: string | null,
  xPoweredBy: string | null,
): HeaderFinding {
  const checkKey = 'SERVER_DISCLOSURE';

  // Patrón: contiene un número de versión (e.g. "Apache/2.4.51", "nginx/1.21.0", "PHP/8.1")
  const versionPattern = /[\w.\-]+\/[\d.]+/i;
  const revealingHeaders: string[] = [];

  if (serverHeader && versionPattern.test(serverHeader)) {
    revealingHeaders.push(`Server: ${serverHeader}`);
  }
  if (xPoweredBy && (versionPattern.test(xPoweredBy) || xPoweredBy.length > 0)) {
    revealingHeaders.push(`X-Powered-By: ${xPoweredBy}`);
  }

  if (revealingHeaders.length > 0) {
    return {
      checkKey,
      category: 'HTTP_HEADERS',
      title: 'Cabeceras revelan información del servidor',
      description: `Las cabeceras exponen tecnologías del servidor: ${revealingHeaders.join(', ')}`,
      status: 'FAILED',
      severity: 'LOW',
      remediation:
        'Elimina o enmascara las cabeceras Server y X-Powered-By para no revelar versiones de software.',
      evidence: { server: serverHeader, xPoweredBy },
    };
  }

  return {
    checkKey,
    category: 'HTTP_HEADERS',
    title: 'No se revelan cabeceras de servidor',
    description: 'Server y X-Powered-By están ausentes o no revelan versiones.',
    status: 'PASSED',
    severity: 'INFO',
    evidence: { server: serverHeader, xPoweredBy },
  };
}

// ---------------------------------------------------------------------------
// Función principal exportada
// ---------------------------------------------------------------------------

/**
 * Audita las 14 cabeceras HTTP de seguridad del documento de requerimientos.
 *
 * @param targetUrl  URL completa del objetivo (ya validada por ssrfGuard)
 * @param headers    Mapa de cabeceras de la respuesta base del objetivo
 * @returns          Array de 14 FindingResult en orden canónico (CR-01..CR-14)
 */
export async function auditHttpHeaders(
  targetUrl: string,
  headers: Record<string, string>,
  signal?: AbortSignal,
): Promise<HeaderFinding[]> {
  const h = (name: string): string | null =>
    headers[name.toLowerCase()] ?? null;

  const findings: HeaderFinding[] = [
    // CR-01
    checkCSP(h('content-security-policy')),
    // CR-02
    checkHSTS(h('strict-transport-security')),
    // CR-03
    checkXFrameOptions(h('x-frame-options')),
    // CR-04
    checkXContentTypeOptions(h('x-content-type-options')),
    // CR-05
    checkReferrerPolicy(h('referrer-policy')),
    // CR-06
    checkPermissionsPolicy(h('permissions-policy')),
    // CR-07
    checkXPermittedCrossDomainPolicies(h('x-permitted-cross-domain-policies')),
    // CR-08 CORS — 4 sondas activas (async)
    await checkCORS(targetUrl, signal),
    // CR-09
    checkCacheControl(h('cache-control')),
    // CR-10
    checkCORP(h('cross-origin-resource-policy')),
    // CR-11
    checkCOOP(h('cross-origin-opener-policy')),
    // CR-12
    checkCOEP(h('cross-origin-embedder-policy')),
    // CR-13
    checkContentType(h('content-type')),
    // CR-14
    checkServerDisclosure(h('server'), h('x-powered-by')),
  ];

  return findings;
}

/** Convierte cabeceras Response en mapa normalizado (lowercase). Excluye Set-Cookie y Authorization. */
export { headersToObject };
