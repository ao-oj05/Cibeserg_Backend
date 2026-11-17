export interface ConnectionFinding {
  ruleKey: string;
  category: "CONNECTION";
  title: string;
  description: string;
  status: "PASSED" | "FAILED";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  remediation?: string;
  rawData?: Record<string, unknown>;
}

export interface ConnectionAuditResult {
  responseTimeMs: number;
  httpsRedirect: boolean;
  findings: ConnectionFinding[];
}

/**
 * Checks server latency, availability, and automatic HTTP-to-HTTPS redirect (BK-02)
 */
export async function auditConnection(host: string, targetUrl: string): Promise<ConnectionAuditResult> {
  const findings: ConnectionFinding[] = [];

  // 1. Measure response time against target URL
  const startTime = performance.now();
  let responseTimeMs = 0;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    await fetch(targetUrl, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "ScanDev-Audit/1.0" },
    });
    responseTimeMs = Math.round(performance.now() - startTime);
  } catch {
    responseTimeMs = Math.round(performance.now() - startTime);
  } finally {
    clearTimeout(timeoutId);
  }

  // Evaluate latency finding
  if (responseTimeMs < 1500) {
    findings.push({
      ruleKey: "RESPONSE_TIME",
      category: "CONNECTION",
      title: "Tiempo de Respuesta del Servidor",
      description: `Excelente tiempo de respuesta: ${responseTimeMs} ms.`,
      status: "PASSED",
      severity: "LOW",
      rawData: { responseTimeMs },
    });
  } else {
    findings.push({
      ruleKey: "RESPONSE_TIME",
      category: "CONNECTION",
      title: "Tiempo de Respuesta Elevado",
      description: `El servidor tardó ${responseTimeMs} ms en responder a la solicitud inicial.`,
      status: "FAILED",
      severity: "LOW",
      remediation: "Optimice el rendimiento del servidor, balanceo de carga o CDN para reducir la latencia.",
      rawData: { responseTimeMs },
    });
  }

  // 2. Check HTTP -> HTTPS redirect
  let httpsRedirect = false;
  const httpController = new AbortController();
  const httpTimeoutId = setTimeout(() => httpController.abort(), 5000);

  try {
    const httpRes = await fetch(`http://${host}`, {
      method: "GET",
      redirect: "manual", // Do not follow redirects automatically
      signal: httpController.signal,
      headers: { "User-Agent": "ScanDev-Audit/1.0" },
    });

    const isRedirectCode = [301, 302, 307, 308].includes(httpRes.status);
    const location = httpRes.headers.get("location") || "";

    if (isRedirectCode && location.startsWith("https://")) {
      httpsRedirect = true;
      findings.push({
        ruleKey: "HTTPS_REDIRECT",
        category: "CONNECTION",
        title: "Redirección Automática HTTPS",
        description: `El tráfico HTTP no seguro redirige automáticamente a HTTPS (${httpRes.status} -> ${location}).`,
        status: "PASSED",
        severity: "HIGH",
        rawData: { statusCode: httpRes.status, redirectLocation: location },
      });
    } else {
      findings.push({
        ruleKey: "HTTPS_REDIRECT",
        category: "CONNECTION",
        title: "Falta Redirección Automática a HTTPS",
        description: "El sitio web permite conexiones HTTP en texto claro sin forzar la redirección a HTTPS.",
        status: "FAILED",
        severity: "HIGH",
        remediation: "Configure una regla de redirección 301 permanente en el servidor web (Nginx/Apache/Caddy) de HTTP a HTTPS.",
        rawData: { statusCode: httpRes.status, location },
      });
    }
  } catch (err) {
    findings.push({
      ruleKey: "HTTPS_REDIRECT",
      category: "CONNECTION",
      title: "Comprobación de Redirección HTTP Fallida",
      description: "No fue posible conectar por el puerto HTTP (80) para verificar redirección.",
      status: "FAILED",
      severity: "MEDIUM",
      rawData: { error: err instanceof Error ? err.message : String(err) },
    });
  } finally {
    clearTimeout(httpTimeoutId);
  }

  return {
    responseTimeMs,
    httpsRedirect,
    findings,
  };
}
