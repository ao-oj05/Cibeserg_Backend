export interface HeaderFinding {
  ruleKey: string;
  category: "HTTP_HEADERS";
  title: string;
  description: string;
  status: "PASSED" | "FAILED";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  remediation?: string;
  rawData?: Record<string, unknown>;
}

export interface HeaderAuditResult {
  statusCode: number;
  findings: HeaderFinding[];
  rawHeaders: Record<string, string>;
}

const SECURITY_HEADERS = [
  {
    key: "strict-transport-security",
    ruleKey: "HSTS",
    name: "Strict-Transport-Security",
    severity: "HIGH" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. El sitio no fuerza HTTPS." };
      const hasMaxAge = /max-age=\d+/i.test(val);
      if (!hasMaxAge) return { pass: false, desc: "HSTS configurado pero sin directiva max-age válida." };
      return { pass: true, desc: `Configurado correctamente: ${val}` };
    },
    remediation: "Configure la cabecera 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' en el servidor web.",
  },
  {
    key: "content-security-policy",
    ruleKey: "CSP",
    name: "Content-Security-Policy",
    severity: "HIGH" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. Vulnerable a ataques de Cross-Site Scripting (XSS) e inyección de datos." };
      return { pass: true, desc: `Política activa detectada: ${val.substring(0, 100)}...` };
    },
    remediation: "Implemente una directiva 'Content-Security-Policy' restringiendo orígenes de scripts, estilos y conexiones.",
  },
  {
    key: "x-frame-options",
    ruleKey: "X_FRAME_OPTIONS",
    name: "X-Frame-Options",
    severity: "MEDIUM" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. Riesgo de ataques de Clickjacking al permitir embeber el sitio en iframes." };
      const normalized = val.toUpperCase().trim();
      if (normalized === "DENY" || normalized === "SAMEORIGIN") {
        return { pass: true, desc: `Protección contra Clickjacking configurada como: ${normalized}` };
      }
      return { pass: false, desc: `Valor no estándar o inseguro: ${val}` };
    },
    remediation: "Configure 'X-Frame-Options: DENY' o 'X-Frame-Options: SAMEORIGIN' en las respuestas HTTP.",
  },
  {
    key: "x-content-type-options",
    ruleKey: "X_CONTENT_TYPE_OPTIONS",
    name: "X-Content-Type-Options",
    severity: "MEDIUM" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. Los navegadores podrían interpretar tipos MIME de forma insegura (MIME sniffing)." };
      if (val.toLowerCase().includes("nosniff")) {
        return { pass: true, desc: "Protección contra MIME Sniffing configurada correctamente (nosniff)." };
      }
      return { pass: false, desc: `Valor inválido: ${val}. Se esperaba 'nosniff'.` };
    },
    remediation: "Configure 'X-Content-Type-Options: nosniff' para evitar la interpretación errónea de contenidos ejecutables.",
  },
  {
    key: "referrer-policy",
    ruleKey: "REFERRER_POLICY",
    name: "Referrer-Policy",
    severity: "LOW" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. Las peticiones salientes podrían filtrar información sensible en la cabecera Referer." };
      const safeValues = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"];
      const isSafe = safeValues.some((s) => val.toLowerCase().includes(s));
      if (isSafe) {
        return { pass: true, desc: `Política de Referrer segura: ${val}` };
      }
      return { pass: false, desc: `Política laxa detectada: ${val}` };
    },
    remediation: "Establezca 'Referrer-Policy: strict-origin-when-cross-origin' para evitar fugas de URLs privadas a terceros.",
  },
  {
    key: "permissions-policy",
    ruleKey: "PERMISSIONS_POLICY",
    name: "Permissions-Policy",
    severity: "LOW" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. No se restringe el acceso a funciones del navegador (cámara, micrófono, geolocalización)." };
      return { pass: true, desc: `Funcionalidades del navegador controladas: ${val.substring(0, 80)}...` };
    },
    remediation: "Declare 'Permissions-Policy: camera=(), microphone=(), geolocation=()' restringiendo APIs sensibles del navegador.",
  },
  {
    key: "x-permitted-cross-domain-policies",
    ruleKey: "X_PERMITTED_CROSS_DOMAIN_POLICIES",
    name: "X-Permitted-Cross-Domain-Policies",
    severity: "LOW" as const,
    validator: (val?: string) => {
      if (!val) return { pass: false, desc: "Cabecera ausente. Podría permitir acceso indebido a clientes Flash, PDF o Silverlight heredados." };
      if (val.toLowerCase().includes("none") || val.toLowerCase().includes("master-only")) {
        return { pass: true, desc: `Políticas de cross-domain restringidas: ${val}` };
      }
      return { pass: false, desc: `Valor laxo: ${val}` };
    },
    remediation: "Defina 'X-Permitted-Cross-Domain-Policies: none' para bloquear políticas cross-domain no autorizadas.",
  },
];

/**
 * Audits the 7 fundamental security HTTP headers using native fetch and 5s timeout (BK-02)
 */
export async function auditHttpHeaders(targetUrl: string): Promise<HeaderAuditResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  let response: Response;
  const rawHeaders: Record<string, string> = {};

  try {
    // Attempt HEAD request first
    response = await fetch(targetUrl, {
      method: "HEAD",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "ScanDev-Security-Scanner/1.0 (+https://scandev.local)",
        Accept: "*/*",
      },
    });

    // If server rejects HEAD (e.g. 405 Method Not Allowed), retry with GET
    if (response.status === 405) {
      response = await fetch(targetUrl, {
        method: "GET",
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent": "ScanDev-Security-Scanner/1.0 (+https://scandev.local)",
          Accept: "*/*",
        },
      });
    }
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error && err.name === "AbortError"
      ? "Timeout de 5 segundos excedido al consultar cabeceras HTTP"
      : `Error de conexión al obtener cabeceras: ${err instanceof Error ? err.message : String(err)}`;
    throw new Error(message);
  } finally {
    clearTimeout(timeoutId);
  }

  // Collect response headers
  response.headers.forEach((val, key) => {
    rawHeaders[key.toLowerCase()] = val;
  });

  const findings: HeaderFinding[] = SECURITY_HEADERS.map((rule) => {
    const val = rawHeaders[rule.key];
    const validation = rule.validator(val);

    return {
      ruleKey: rule.ruleKey,
      category: "HTTP_HEADERS",
      title: `Cabecera ${rule.name}`,
      description: validation.desc,
      status: validation.pass ? "PASSED" : "FAILED",
      severity: rule.severity,
      remediation: validation.pass ? undefined : rule.remediation,
      rawData: { header: rule.name, value: val ?? null },
    };
  });

  return {
    statusCode: response.status,
    findings,
    rawHeaders,
  };
}
