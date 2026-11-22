import dns from "dns/promises";
import net from "net";

/**
 * Checks if an IPv4 address is within private, loopback, link-local, or reserved ranges
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed IP is treated as unsafe
  }

  const [p0, p1] = parts;

  // 0.0.0.0/8 (Current network)
  if (p0 === 0) return true;

  // 127.0.0.0/8 (Loopback)
  if (p0 === 127) return true;

  // 10.0.0.0/8 (Private-Use)
  if (p0 === 10) return true;

  // 172.16.0.0/12 (Private-Use: 172.16.0.0 - 172.31.255.255)
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;

  // 192.168.0.0/16 (Private-Use)
  if (p0 === 192 && p1 === 168) return true;

  // 169.254.0.0/16 (Link-Local & Cloud Metadata e.g. 169.254.169.254)
  if (p0 === 169 && p1 === 254) return true;

  // 100.64.0.0/10 (Carrier-grade NAT)
  if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;

  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Test-Net documentation)
  if (p0 === 192 && p1 === 0 && parts[2] === 2) return true;
  if (p0 === 198 && p1 === 51 && parts[2] === 100) return true;
  if (p0 === 203 && p1 === 0 && parts[2] === 113) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (p0 >= 224) return true;

  return false;
}

/**
 * Checks if an IPv6 address is private, loopback, link-local, or documentation
 */
function isPrivateIPv6(ip: string): boolean {
  const firstGroup = ip.toLowerCase().split(':')[0];
  const firstValue = firstGroup ? Number.parseInt(firstGroup, 16) : 0;
  if (firstValue < 0x2000 || firstValue > 0x3fff) return true;

  const normalized = ip.toLowerCase();
  return (
    normalized.startsWith('2001:0:') ||
    normalized.startsWith('2001:2:') ||
    normalized.startsWith('2001:10:') ||
    normalized.startsWith('2001:db8:') ||
    normalized.startsWith('2002:')
  );
}

export interface SSRFValidationResult {
  host: string;
  ipAddress: string;
  normalizedUrl: string;
}

/**
 * Validates domain and prevents SSRF attacks against internal network (BK-01)
 */
export async function validateTargetAgainstSSRF(
  rawUrl: string,
  signal?: AbortSignal,
): Promise<SSRFValidationResult> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw new Error("URL con formato inválido");
  }

  // 1. Strict Protocol Validation
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(`Protocolo no permitido: ${parsedUrl.protocol}. Sólo se permite http: y https:`);
  }

  // 2. Reject credentials in URL
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error("No se permiten credenciales en la URL objetivo");
  }

  const host = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // 3. Block localhost domain patterns
  const blockedHostPatterns = [
    "localhost",
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".arpa",
  ];
  if (blockedHostPatterns.some((pattern) => host === pattern || host.endsWith(pattern))) {
    throw new Error(`Dominio no permitido por seguridad interna (SSRF): ${host}`);
  }

  // 4. DNS Resolution & IP Range Check
  let addresses: Array<{ address: string; family: number }>;
  try {
    const literalFamily = net.isIP(host);
    if (literalFamily) {
      addresses = [{ address: host, family: literalFamily }];
    } else {
      const lookup = dns.lookup(host, { all: true });
      if (!signal) {
        addresses = await lookup;
      } else {
        addresses = await new Promise((resolve, reject) => {
          const abort = () => reject(signal.reason ?? new Error('DNS lookup aborted'));
          signal.addEventListener('abort', abort, { once: true });
          if (signal.aborted) abort();
          lookup.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
        });
      }
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : "Error desconocido en resolución DNS";
    throw new Error(`No fue posible resolver el dominio ${host}: ${errorMsg}`);
  }

  if (!addresses || addresses.length === 0) {
    throw new Error(`El dominio ${host} no resolvió ninguna dirección IP`);
  }

  // Check every resolved address against private/local networks
  for (const addr of addresses) {
    const ip = addr.address;
    const isIP = net.isIP(ip);

    if (isIP === 4 && isPrivateIPv4(ip)) {
      throw new Error(`Acceso bloqueado: la IP resuelta ${ip} pertenece a un rango privado/local restringido (SSRF)`);
    } else if (isIP === 6 && isPrivateIPv6(ip)) {
      throw new Error(`Acceso bloqueado: la dirección IPv6 ${ip} pertenece a un rango privado/local restringido (SSRF)`);
    }
  }

  return {
    host,
    ipAddress: addresses[0].address,
    normalizedUrl: parsedUrl.toString(),
  };
}
