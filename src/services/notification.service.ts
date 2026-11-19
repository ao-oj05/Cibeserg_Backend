/**
 * @module notification.service
 * @description Servicio de notificaciones internas de seguridad (SOA).
 *
 * Exporta tanto la clase (NotificationService) como la instancia singleton
 * (notificationService) para uso en el orquestador del scanner.
 */

import { prisma } from '@/lib/db';
import { NotificationType } from '@prisma/client';

export interface CreateNotificationDto {
  userId: string;
  title: string;
  message: string;
  type?: NotificationType;
}

export class NotificationService {
  /**
   * Obtiene las notificaciones no leídas de un usuario (BK-05).
   */
  async getUnread(userId: string) {
    return NotificationService.getUnread(userId);
  }

  static async getUnread(userId: string) {
    const notifications = await prisma.notification.findMany({
      where: { userId, isRead: false },
      orderBy: { createdAt: 'desc' },
    });
    return { data: notifications, unreadCount: notifications.length };
  }

  /**
   * Marca notificaciones como leídas (BK-05 — sólo del propio usuario).
   */
  async markAsRead(userId: string, notificationIds?: string[]) {
    return NotificationService.markAsRead(userId, notificationIds);
  }

  static async markAsRead(userId: string, notificationIds?: string[]) {
    if (notificationIds && notificationIds.length > 0) {
      const result = await prisma.notification.updateMany({
        where: { id: { in: notificationIds }, userId },
        data: { isRead: true },
      });
      return { count: result.count };
    }
    const result = await prisma.notification.updateMany({
      where: { userId, isRead: false },
      data: { isRead: true },
    });
    return { count: result.count };
  }

  /**
   * Crea una notificación interna de seguridad.
   */
  async create(dto: CreateNotificationDto) {
    return NotificationService.create(dto);
  }

  static async create(dto: CreateNotificationDto) {
    try {
      return await prisma.notification.create({
        data: {
          userId: dto.userId,
          title: dto.title,
          message: dto.message,
          type: dto.type ?? 'SYSTEM',
        },
      });
    } catch (err) {
      // No bloqueante — el fallo en notificación no debe interrumpir el escaneo
      console.error('[NotificationService:create] Error:', err);
      return null;
    }
  }
}

/** Instancia singleton exportada para uso en el orquestador del scanner */
export const notificationService = new NotificationService();
