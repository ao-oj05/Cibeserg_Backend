import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import {
  verifyPassword,
  createSessionToken,
  getSessionCookieOptions,
} from "@/lib/auth";
import { LoginSchema } from "@/lib/validators";

export async function POST(req: NextRequest) {
  const ipAddress = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "127.0.0.1";
  const userAgent = req.headers.get("user-agent") || "Unknown";

  try {
    const body = await req.json();
    const parseResult = LoginSchema.safeParse(body);

    if (!parseResult.success) {
      return NextResponse.json(
        { error: "Credenciales incompletas o malformadas" },
        { status: 400 }
      );
    }

    const { email, password } = parseResult.data;

    // Retrieve user by email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      await prisma.auditLog.create({
        data: {
          action: "LOGIN_FAILED",
          ipAddress,
          userAgent,
          metadata: { reason: "Usuario no encontrado", email },
        },
      });

      return NextResponse.json(
        { error: "Credenciales de acceso incorrectas" },
        { status: 401 }
      );
    }

    // Verify Password Hash
    const isValid = await verifyPassword(password, user.passwordHash);

    if (!isValid) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: "LOGIN_FAILED",
          ipAddress,
          userAgent,
          metadata: { reason: "Contraseña incorrecta" },
        },
      });

      return NextResponse.json(
        { error: "Credenciales de acceso incorrectas" },
        { status: 401 }
      );
    }

    // Register LOGIN_SUCCESS in AuditLog
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: "LOGIN_SUCCESS",
        ipAddress,
        userAgent,
      },
    });

    // Create Session JWT
    const token = await createSessionToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    const response = NextResponse.json({
      message: "Inicio de sesión exitoso",
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    });

    // Set Secure HttpOnly Session Cookie (BK-04)
    const cookieOpts = getSessionCookieOptions();
    response.cookies.set({
      name: cookieOpts.name,
      value: token,
      httpOnly: cookieOpts.httpOnly,
      secure: cookieOpts.secure,
      sameSite: cookieOpts.sameSite,
      path: cookieOpts.path,
      maxAge: cookieOpts.maxAge,
    });

    return response;
  } catch (err: unknown) {
    console.error("[Auth:Login] Error interno:", err);
    return NextResponse.json(
      { error: "Error en el servidor al autenticar el usuario" },
      { status: 500 }
    );
  }
}
