import { NextRequest, NextResponse } from "next/server";
import { LoginSchema } from "@/lib/validators";
import { AuthService } from "@/services/auth.service";
import { getSessionCookieOptions } from "@/lib/auth";
import { getRateLimitStatus, recordRateLimitHit } from "@/lib/rate-limit";

const LOGIN_ATTEMPT_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60_000;

function recordFailedLogin(email: string | null, ipAddress: string): void {
  const options = { limit: LOGIN_ATTEMPT_LIMIT, windowMs: LOGIN_WINDOW_MS };
  if (email) recordRateLimitHit(`login-email:${email}`, options);
  recordRateLimitHit(`login-ip:${ipAddress}`, options);
}

export async function POST(req: NextRequest) {
  const ipAddress = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "127.0.0.1";
  const userAgent = req.headers.get("user-agent") || "Unknown";
  let loginEmail: string | null = null;

  try {
    const body = await req.json();
    const parseResult = LoginSchema.safeParse(body);

    if (!parseResult.success) {
      return NextResponse.json(
        { error: "Credenciales incompletas o malformadas" },
        { status: 400 }
      );
    }

    loginEmail = parseResult.data.email;
    const emailRateLimitKey = `login-email:${loginEmail}`;
    const ipRateLimitKey = `login-ip:${ipAddress}`;
    const rateLimitOptions = { limit: LOGIN_ATTEMPT_LIMIT, windowMs: LOGIN_WINDOW_MS };
    const emailLimit = getRateLimitStatus(emailRateLimitKey, rateLimitOptions);
    const ipLimit = getRateLimitStatus(ipRateLimitKey, rateLimitOptions);
    if (!emailLimit.success || !ipLimit.success) {
      return NextResponse.json(
        { error: "Demasiados intentos de inicio de sesión. Intente nuevamente más tarde." },
        { status: 429 },
      );
    }

    const { token, user } = await AuthService.login(parseResult.data, {
      ipAddress,
      userAgent,
    });

    const response = NextResponse.json({
      message: "Inicio de sesión exitoso",
      user,
    });

    // Set HttpOnly, Secure and SameSite=Lax cookie (BK-04)
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
    const message = err instanceof Error ? err.message : "Error al iniciar sesión";
    if (message.startsWith("INVALID_CREDENTIALS:")) {
      recordFailedLogin(loginEmail, ipAddress);
      return NextResponse.json({ error: message.replace("INVALID_CREDENTIALS:", "") }, { status: 401 });
    }
    if (message.startsWith("ACCOUNT_SUSPENDED:")) {
      recordFailedLogin(loginEmail, ipAddress);
      return NextResponse.json({ error: message.replace("ACCOUNT_SUSPENDED:", "") }, { status: 403 });
    }
    console.error("[Auth:Login] Error:", err);
    return NextResponse.json({ error: "Error interno al autenticar usuario" }, { status: 500 });
  }
}
