/**
 * @module audit.service
 * @description Servicio transversal de auditoría — registra eventos de seguridad
 * y operacionales en la tabla audit_logs.
 *
 * Exporta tanto la clase (AuditService) como la instancia singleton (auditService)
 * para compatibilidad con el orquestador del scanner que usa auditService.log().
 */

import { prisma } from '@/lib/db';
import { AuditAction, Prisma } from '@prisma/client';

export interface LogAuditEventParams {
  userId?: string | null;
  action: AuditAction;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Prisma.InputJsonValue;
}

export class AuditService {
  /**
   * Registra un evento de auditoría en la base de datos.
   * Los errores son no-bloqueantes para no interrumpir el flujo principal.
   */
  async log(params: LogAuditEventParams) {
    return AuditService.log(params);
  }

  /**
   * Versión estática del método log (para compatibilidad con código legado).
   */
  static async log(params: LogAuditEventParams) {
    try {
      return await prisma.auditLog.create({
        data: {
          userId: params.userId ?? null,
          action: params.action,
          ipAddress: params.ipAddress ?? null,
          userAgent: params.userAgent ?? null,
          metadata: params.metadata ?? Prisma.JsonNull,
        },
      });
    } catch (err) {
      // No bloqueante — un fallo en auditoría nunca debe romper la operación principal
      console.error('[AuditService:log] Error al registrar evento:', err);
      return null;
    }
  }
}

/** Instancia singleton exportada para uso en servicios y el orquestador del scanner */
export const auditService = new AuditService();
