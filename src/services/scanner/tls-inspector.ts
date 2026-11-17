import tls from "tls";

export interface TLSFinding {
  ruleKey: string;
  category: "TLS_SSL";
  title: string;
  description: string;
  status: "PASSED" | "FAILED";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  remediation?: string;
  rawData?: Record<string, unknown>;
}

export interface TLSInspectionResult {
  sslValid: boolean;
  sslIssuer: string | null;
  sslDaysLeft: number | null;
  sslProtocol: string | null;
  findings: TLSFinding[];
}

/**
 * Connects directly to port 443 via TLS socket to audit SSL certificate and cipher protocols
 */
export async function inspectTLS(host: string): Promise<TLSInspectionResult> {
  return new Promise((resolve) => {
    const findings: TLSFinding[] = [];
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host, // SNI support
        timeout: 5000,
        rejectUnauthorized: false, // We check authorization manually to report clear findings
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          const isAuthorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            findings.push({
              ruleKey: "SSL_CERT_PRESENT",
              category: "TLS_SSL",
              title: "Certificado SSL/TLS no entregado",
              description: "El servidor no proporcionó un certificado X.509 válido en el puerto 443.",
              status: "FAILED",
              severity: "CRITICAL",
              remediation: "Instale un certificado SSL/TLS válido para habilitar HTTPS en el dominio.",
            });

            socket.destroy();
            return resolve({
              sslValid: false,
              sslIssuer: null,
              sslDaysLeft: null,
              sslProtocol: protocol || null,
              findings,
            });
          }

          // 1. Issuer extraction
          const issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || "Desconocido") : "Desconocido";

          // 2. Expiration calculation
          const validToDate = new Date(cert.valid_to);
          const now = Date.now();
          const sslDaysLeft = Math.floor((validToDate.getTime() - now) / (1000 * 60 * 60 * 24));

          // Finding 1: Certificate Authority & Validity
          if (isAuthorized) {
            findings.push({
              ruleKey: "SSL_VALIDITY",
              category: "TLS_SSL",
              title: "Validez del Certificado SSL/TLS",
              description: `Certificado válido emitido por una entidad de certificación de confianza (${issuer}).`,
              status: "PASSED",
              severity: "HIGH",
              rawData: { issuer, validFrom: cert.valid_from, validTo: cert.valid_to },
            });
          } else {
            findings.push({
              ruleKey: "SSL_VALIDITY",
              category: "TLS_SSL",
              title: "Certificado SSL/TLS Inválido o Autofirmado",
              description: `Fallo de validación de confianza: ${authError || "Cadena de certificación no confiable"}.`,
              status: "FAILED",
              severity: "CRITICAL",
              remediation: "Renueve o reemplace el certificado con uno firmado por una Autoridad Certificadora reconocida (ej. Let's Encrypt).",
              rawData: { authError, issuer },
            });
          }

          // Finding 2: Expiration Window
          if (sslDaysLeft > 15) {
            findings.push({
              ruleKey: "SSL_EXPIRATION",
              category: "TLS_SSL",
              title: "Vigencia del Certificado SSL",
              description: `El certificado expira en ${sslDaysLeft} días (${validToDate.toLocaleDateString()}).`,
              status: "PASSED",
              severity: "MEDIUM",
              rawData: { daysLeft: sslDaysLeft, validTo: cert.valid_to },
            });
          } else if (sslDaysLeft > 0) {
            findings.push({
              ruleKey: "SSL_EXPIRATION",
              category: "TLS_SSL",
              title: "Certificado SSL Próximo a Expirar",
              description: `Alerta: El certificado expira en menos de 15 días (${sslDaysLeft} días restantes).`,
              status: "FAILED",
              severity: "HIGH",
              remediation: "Inicie el proceso de renovación del certificado de forma inmediata antes de su expiración.",
              rawData: { daysLeft: sslDaysLeft, validTo: cert.valid_to },
            });
          } else {
            findings.push({
              ruleKey: "SSL_EXPIRATION",
              category: "TLS_SSL",
              title: "Certificado SSL Expirado",
              description: `El certificado expiró hace ${Math.abs(sslDaysLeft)} días (${validToDate.toLocaleDateString()}).`,
              status: "FAILED",
              severity: "CRITICAL",
              remediation: "El certificado está vencido. Genere un nuevo certificado SSL/TLS de inmediato.",
              rawData: { daysLeft: sslDaysLeft, validTo: cert.valid_to },
            });
          }

          // Finding 3: TLS Protocol Version
          const isModernTLS = protocol === "TLSv1.2" || protocol === "TLSv1.3";
          if (isModernTLS) {
            findings.push({
              ruleKey: "TLS_PROTOCOL",
              category: "TLS_SSL",
              title: "Protocolo Criptográfico TLS",
              description: `Uso de protocolo criptográfico seguro y moderno: ${protocol}.`,
              status: "PASSED",
              severity: "HIGH",
              rawData: { protocol },
            });
          } else {
            findings.push({
              ruleKey: "TLS_PROTOCOL",
              category: "TLS_SSL",
              title: "Protocolo Criptográfico Anticuado",
              description: `El servidor negoció ${protocol || "versión obsoleta"}. Versiones anteriores a TLS 1.2 son vulnerables (ej. POODLE, BEAST).`,
              status: "FAILED",
              severity: "HIGH",
              remediation: "Deshabilite SSLv3, TLS 1.0 y TLS 1.1 en la configuración de su servidor web/proxy y active TLS 1.2 y TLS 1.3.",
              rawData: { protocol },
            });
          }

          socket.destroy();
          resolve({
            sslValid: isAuthorized && sslDaysLeft > 0,
            sslIssuer: issuer,
            sslDaysLeft,
            sslProtocol: protocol || null,
            findings,
          });
        } catch (err: unknown) {
          socket.destroy();
          resolve({
            sslValid: false,
            sslIssuer: null,
            sslDaysLeft: null,
            sslProtocol: null,
            findings: [
              {
                ruleKey: "TLS_ERROR",
                category: "TLS_SSL",
                title: "Fallo durante inspección TLS",
                description: `Error al extraer detalles TLS: ${err instanceof Error ? err.message : String(err)}`,
                status: "FAILED",
                severity: "HIGH",
              },
            ],
          });
        }
      }
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        sslValid: false,
        sslIssuer: null,
        sslDaysLeft: null,
        sslProtocol: null,
        findings: [
          {
            ruleKey: "TLS_TIMEOUT",
            category: "TLS_SSL",
            title: "Timeout de conexión TLS",
            description: "Tiempo de espera agotado al conectar al puerto 443 con TLS.",
            status: "FAILED",
            severity: "HIGH",
            remediation: "Verifique que el firewall del servidor permita tráfico entrante al puerto TCP 443.",
          },
        ],
      });
    });

    socket.on("error", (err) => {
      socket.destroy();
      resolve({
        sslValid: false,
        sslIssuer: null,
        sslDaysLeft: null,
        sslProtocol: null,
        findings: [
          {
            ruleKey: "TLS_CONNECTION_ERROR",
            category: "TLS_SSL",
            title: "Puerto 443 no disponible o sin soporte SSL",
            description: `No se pudo establecer el handshake TLS: ${err.message}`,
            status: "FAILED",
            severity: "HIGH",
            remediation: "Asegúrese de que el servidor web escuche conexiones HTTPS en el puerto 443.",
          },
        ],
      });
    });
  });
}
