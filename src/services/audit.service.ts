import { prisma } from "@/lib/db";
import { AuditAction, Prisma } from "@prisma/client";

export interface LogAuditEventParams {
  userId?: string | null;
  action: AuditAction;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Prisma.InputJsonValue;
}

export class AuditService {
  /**
   * Logs security and operational events to the database
   */
  static async log(params: LogAuditEventParams) {
    try {
      return await prisma.auditLog.create({
        data: {
          userId: params.userId || null,
          action: params.action,
          ipAddress: params.ipAddress || null,
          userAgent: params.userAgent || null,
          metadata: params.metadata || Prisma.JsonNull,
        },
      });
    } catch (err) {
      console.error("[AuditService:log] Error al registrar evento:", err);
      // Non-blocking error: avoid breaking main transaction for logging
      return null;
    }
  }
}
