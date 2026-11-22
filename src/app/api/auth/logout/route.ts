import { NextRequest, NextResponse } from "next/server";
import { getSessionUser, AUTH_COOKIE_NAME } from "@/lib/auth";
import { AuthService } from "@/services/auth.service";
import { getClientIp } from "@/lib/client-ip";

export async function POST(req: NextRequest) {
  const ipAddress = getClientIp(req) || "unknown";
  const userAgent = req.headers.get("user-agent") || "Unknown";

  const session = await getSessionUser(req);

  await AuthService.logout(session?.userId || null, {
    ipAddress,
    userAgent,
  });

  const response = NextResponse.json({
    message: "Sesión cerrada correctamente",
  });

  response.cookies.delete(AUTH_COOKIE_NAME);
  return response;
}
