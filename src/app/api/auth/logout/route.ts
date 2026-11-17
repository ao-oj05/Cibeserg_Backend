import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUser, AUTH_COOKIE_NAME } from "@/lib/auth";

export async function POST(req: NextRequest) {
  const ipAddress = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "127.0.0.1";
  const userAgent = req.headers.get("user-agent") || "Unknown";

  const session = await getSessionUser(req);

  if (session) {
    await prisma.auditLog.create({
      data: {
        userId: session.userId,
        action: "LOGOUT",
        ipAddress,
        userAgent,
      },
    });
  }

  const response = NextResponse.json({
    message: "Sesión cerrada correctamente",
  });

  // Clear cookie
  response.cookies.delete(AUTH_COOKIE_NAME);

  return response;
}
