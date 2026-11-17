import { prisma } from "@/lib/db";
import { checkRateLimit } from "@/lib/rate-limit";
import { escapeSqlLike } from "@/lib/validators";
import { executeSecurityScan } from "./scanner";
import { AuditService } from "./audit.service";

export interface ListScansOptions {
  page?: number;
  limit?: number;
  host?: string;
}

export class ScanService {
  /**
   * Executes a full cybersecurity passive scan with rate limiting and audit tracking
   */
  static async startScan(userId: string, targetUrl: string, ipAddress: string) {
    // 1. Rate Limiting Check (BK-02)
    const rateLimit = checkRateLimit(`scan:${userId}`, { limit: 10, windowMs: 60_000 });
    if (!rateLimit.success) {
      throw new Error(`RATE_LIMIT:Límite excedido. Intente en ${Math.ceil(rateLimit.resetMs / 1000)} segundos.`);
    }

    // 2. Audit Start
    await AuditService.log({
      userId,
      action: "SCAN_STARTED",
      ipAddress,
      metadata: { targetUrl },
    });

    // 3. Execute Scan
    const scanResult = await executeSecurityScan({ userId, targetUrl });

    // 4. Audit Completed
    await AuditService.log({
      userId,
      action: "SCAN_COMPLETED",
      ipAddress,
      metadata: { scanId: scanResult.id, riskScore: scanResult.riskScore },
    });

    return scanResult;
  }

  /**
   * Retrieves paginated scan history strictly isolated by userId (BK-05)
   */
  static async listUserScans(userId: string, options: ListScansOptions = {}) {
    const page = options.page && options.page > 0 ? options.page : 1;
    const limit = options.limit && options.limit > 0 && options.limit <= 100 ? options.limit : 10;
    const skip = (page - 1) * limit;

    const where: {
      userId: string;
      host?: { contains: string; mode: "insensitive" };
    } = {
      userId,
    };

    if (options.host) {
      const sanitized = escapeSqlLike(options.host);
      where.host = {
        contains: sanitized,
        mode: "insensitive",
      };
    }

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: limit,
        select: {
          id: true,
          targetUrl: true,
          host: true,
          ipAddress: true,
          riskScore: true,
          status: true,
          responseTimeMs: true,
          httpsRedirect: true,
          sslValid: true,
          sslIssuer: true,
          sslDaysLeft: true,
          sslProtocol: true,
          startedAt: true,
          completedAt: true,
          createdAt: true,
          _count: {
            select: { findings: true },
          },
        },
      }),
      prisma.scan.count({ where }),
    ]);

    return {
      data: scans,
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Retrieves full details and findings of a scan (BK-05)
   */
  static async getScanDetail(userId: string, scanId: string) {
    const scan = await prisma.scan.findFirst({
      where: {
        id: scanId,
        userId,
      },
      include: {
        findings: {
          orderBy: { createdAt: "asc" },
        },
      },
    });

    if (!scan) {
      throw new Error("NOT_FOUND:Escaneo no encontrado o sin autorización");
    }

    return scan;
  }

  /**
   * Deletes a scan and cascades findings
   */
  static async deleteScan(userId: string, scanId: string) {
    const existing = await prisma.scan.findFirst({
      where: {
        id: scanId,
        userId,
      },
    });

    if (!existing) {
      throw new Error("NOT_FOUND:Escaneo no encontrado o sin autorización");
    }

    await prisma.scan.delete({
      where: { id: scanId },
    });

    return { success: true };
  }
}
