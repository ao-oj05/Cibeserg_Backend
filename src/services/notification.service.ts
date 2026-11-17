import { prisma } from "@/lib/db";
import { NotificationType } from "@prisma/client";

export interface CreateNotificationDto {
  userId: string;
  title: string;
  message: string;
  type?: NotificationType;
}

export class NotificationService {
  /**
   * Retrieves unread notifications for a specific user
   */
  static async getUnread(userId: string) {
    const notifications = await prisma.notification.findMany({
      where: {
        userId,
        isRead: false,
      },
      orderBy: { createdAt: "desc" },
    });

    return {
      data: notifications,
      unreadCount: notifications.length,
    };
  }

  /**
   * Marks specified or all unread notifications as read
   */
  static async markAsRead(userId: string, notificationIds?: string[]) {
    if (notificationIds && notificationIds.length > 0) {
      const result = await prisma.notification.updateMany({
        where: {
          id: { in: notificationIds },
          userId,
        },
        data: { isRead: true },
      });
      return { count: result.count };
    }

    // If no IDs provided, mark all unread for user
    const result = await prisma.notification.updateMany({
      where: {
        userId,
        isRead: false,
      },
      data: { isRead: true },
    });

    return { count: result.count };
  }

  /**
   * Creates an internal security notification
   */
  static async create(dto: CreateNotificationDto) {
    return await prisma.notification.create({
      data: {
        userId: dto.userId,
        title: dto.title,
        message: dto.message,
        type: dto.type || "SYSTEM",
      },
    });
  }
}
