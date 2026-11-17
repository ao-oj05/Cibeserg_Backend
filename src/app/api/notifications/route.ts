import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth";
import { UpdateNotificationsSchema } from "@/lib/validators";
import { NotificationService } from "@/services/notification.service";

/**
 * GET /api/notifications
 * Delegates to NotificationService.getUnread (BK-05)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const result = await NotificationService.getUnread(session.userId);
    return NextResponse.json(result);
  } catch (err: unknown) {
    console.error("[Notifications:GET] Error:", err);
    return NextResponse.json({ error: "Error al recuperar notificaciones" }, { status: 500 });
  }
}

/**
 * PATCH /api/notifications
 * Delegates to NotificationService.markAsRead
 */
export async function PATCH(req: NextRequest) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await req.json();
    const parseResult = UpdateNotificationsSchema.safeParse(body);

    const notificationIds = parseResult.success ? parseResult.data.notificationIds : undefined;
    const { count } = await NotificationService.markAsRead(session.userId, notificationIds);

    return NextResponse.json({
      message: `${count} notificaciones actualizadas como leídas`,
    });
  } catch (err: unknown) {
    console.error("[Notifications:PATCH] Error:", err);
    return NextResponse.json({ error: "Error al actualizar notificaciones" }, { status: 500 });
  }
}
