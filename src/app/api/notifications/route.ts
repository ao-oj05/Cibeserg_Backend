import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";
import { UpdateNotificationsSchema } from "@/lib/validators";

/**
 * GET /api/notifications
 * Retrieves unread security alerts and notifications for the user (BK-05)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const notifications = await prisma.notification.findMany({
      where: {
        userId: session.userId,
        isRead: false,
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json({
      data: notifications,
      unreadCount: notifications.length,
    });
  } catch (err: unknown) {
    console.error("[Notifications:GET] Error:", err);
    return NextResponse.json(
      { error: "Error al recuperar notificaciones" },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/notifications
 * Marks notifications as read
 */
export async function PATCH(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await req.json();
    const parseResult = UpdateNotificationsSchema.safeParse(body);

    if (!parseResult.success) {
      // If no specific IDs provided, mark ALL unread notifications as read for this user
      await prisma.notification.updateMany({
        where: {
          userId: session.userId,
          isRead: false,
        },
        data: {
          isRead: true,
        },
      });

      return NextResponse.json({
        message: "Todas las notificaciones fueron marcadas como leídas",
      });
    }

    const { notificationIds } = parseResult.data;

    // Update only notifications owned by the authenticated user
    const updated = await prisma.notification.updateMany({
      where: {
        id: { in: notificationIds },
        userId: session.userId,
      },
      data: {
        isRead: true,
      },
    });

    return NextResponse.json({
      message: `${updated.count} notificaciones actualizadas como leídas`,
    });
  } catch (err: unknown) {
    console.error("[Notifications:PATCH] Error:", err);
    return NextResponse.json(
      { error: "Error al actualizar notificaciones" },
      { status: 500 }
    );
  }
}
