/**
 * @module scan.service
 * @description Servicio de escaneos de ScanDev (SOA — capa de negocio).
 *
 * Requerimientos de seguridad:
 * - BK-02: Rate limiting 10 escaneos/hora por usuario
 * - BK-03: Validación Zod delegada al controlador (route.ts)
 * - BK-05: Aislamiento estricto por userId en todas las consultas
 * - BK-06: Mensajes genéricos al cliente; detalles sólo en servidor
 * - RS-02: confirmedOwnership = true obligatorio para iniciar escaneo
 */

import { prisma } from '@/lib/db';
import { checkRateLimit } from '@/lib/rate-limit';
import { escapeSqlLike } from '@/lib/validators';
import { AuditService } from './audit.service';
import { enqueueScan } from './scan-queue';

export interface ListScansOptions {
  page?: number;
  limit?: number;
  host?: string;
}

export class ScanService {
  /**
   * Crea un escaneo en PENDING y lo entrega al worker en segundo plano.
   *
   * @param userId             ID del usuario autenticado (BK-05)
   * @param targetUrl          URL del objetivo (ya validada con Zod en el controlador)
   * @param ipAddress          IP del cliente (para auditoría)
   * @param confirmedOwnership Debe ser true (RS-02)
   */
  static async startScan(
    userId: string,
    targetUrl: string,
    ipAddress: string,
    confirmedOwnership: boolean,
  ) {
    // RS-02: Rechazo inmediato si no hay confirmación de propiedad
    if (!confirmedOwnership) {
      throw new Error('RS-02:Debes confirmar que eres propietario del dominio antes de escanearlo.');
    }

    const rateLimit = checkRateLimit(`scan:${userId}`, {
      limit: 10,
      windowMs: 60 * 60_000,
    });
    if (!rateLimit.success) {
      throw new Error(
        `RATE_LIMIT:Límite de 10 escaneos por hora excedido. Intente en ${Math.ceil(rateLimit.resetMs / 60_000)} minutos.`,
      );
    }

    // Extraer host para guardar en el modelo
    const urlObj = new URL(targetUrl);
    const host = urlObj.hostname;

    // 1. Crear el scan en estado PENDING (antes de cualquier petición de red)
    const scan = await prisma.scan.create({
      data: {
        userId,
        targetUrl,
        host,
        status: 'PENDING',
        confirmedOwnership: true,
      },
    });

    // 2. Registrar evento de auditoría SCAN_CREATED (no SCAN_STARTED)
    await AuditService.log({
      userId,
      action: 'SCAN_CREATED',
      ipAddress,
      metadata: { scanId: scan.id, targetUrl },
    });

    const queued = enqueueScan({
      scanId: scan.id,
      userId,
      targetUrl,
      confirmedOwnership,
    });
    if (!queued) {
      await prisma.scan.updateMany({
        where: { id: scan.id, userId },
        data: { status: 'FAILED', completedAt: new Date() },
      });
      throw new Error('QUEUE_FULL:El servicio está ocupado. Intenta de nuevo más tarde.');
    }

    return scan;
  }

  /**
   * Lista escaneos del usuario con paginación (BK-05 — aislamiento por userId).
   */
  static async listUserScans(userId: string, options: ListScansOptions = {}) {
    const page = options.page && options.page > 0 ? options.page : 1;
    const limit =
      options.limit && options.limit > 0 && options.limit <= 100 ? options.limit : 10;
    const skip = (page - 1) * limit;

    const where: {
      userId: string;
      host?: { contains: string; mode: 'insensitive' };
    } = { userId };

    if (options.host) {
      const sanitized = escapeSqlLike(options.host);
      where.host = { contains: sanitized, mode: 'insensitive' };
    }

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          targetUrl: true,
          host: true,
          ipAddress: true,
          riskScore: true,
          riskLevel: true,
          status: true,
          responseTimeMs: true,
          httpsRedirect: true,
          sslValid: true,
          sslIssuer: true,
          sslDaysLeft: true,
          sslProtocol: true,
          confirmedOwnership: true,
          startedAt: true,
          completedAt: true,
          createdAt: true,
          _count: { select: { findings: true } },
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
   * Devuelve detalle completo de un escaneo con sus 19 findings (BK-05).
   */
  static async getScanDetail(userId: string, scanId: string) {
    const scan = await prisma.scan.findFirst({
      where: { id: scanId, userId },
      include: {
        findings: { orderBy: { createdAt: 'asc' } },
      },
    });

    if (!scan) {
      throw new Error('NOT_FOUND:Escaneo no encontrado o sin autorización.');
    }

    return scan;
  }

  /**
   * Elimina un escaneo y sus findings en cascada (BK-05).
   */
  static async deleteScan(userId: string, scanId: string) {
    const result = await prisma.scan.deleteMany({
      where: { id: scanId, userId },
    });
    if (result.count === 0) {
      throw new Error('NOT_FOUND:Escaneo no encontrado o sin autorización.');
    }

    return { success: true };
  }
}
