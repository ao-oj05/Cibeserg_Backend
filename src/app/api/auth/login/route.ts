import { NextRequest, NextResponse } from "next/server";
import { LoginSchema } from "@/lib/validators";
import { AuthService } from "@/services/auth.service";
import { getSessionCookieOptions } from "@/lib/auth";
import { getRateLimitStatus, recordRateLimitHit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/client-ip";

const LOGIN_ATTEMPT_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60_000;

async function recordFailedLogin(email: string | null, ipAddress: string): Promise<void> {
  const options = { limit: LOGIN_ATTEMPT_LIMIT, windowMs: LOGIN_WINDOW_MS };
  const keys = [
    ...(email ? [`login-email:${email}`] : []),
    `login-ip:${ipAddress}`,
  ];
  await Promise.all(keys.map((key) => recordRateLimitHit(key, options)));
}

async function failedLoginResponse(
  email: string | null,
  ipAddress: string,
  error: string,
  status: number,
): Promise<NextResponse> {
  try {
    await recordFailedLogin(email, ipAddress);
  } catch (rateLimitError: unknown) {
    console.error("[Auth:Login] Could not record failed login", rateLimitError);
    return NextResponse.json(
      { error: "Error interno al autenticar usuario" },
      { status: 500 },
    );
  }
  return NextResponse.json({ error }, { status });
}

export async function POST(req: NextRequest) {
  const ipAddress = getClientIp(req);
  if (!ipAddress) {
    return NextResponse.json({ error: "No se pudo determinar la IP del cliente" }, { status: 503 });
  }
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
    const [emailLimit, ipLimit] = await Promise.all([
      getRateLimitStatus(emailRateLimitKey, rateLimitOptions),
      getRateLimitStatus(ipRateLimitKey, rateLimitOptions),
    ]);
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
      return failedLoginResponse(
        loginEmail,
        ipAddress,
        message.replace("INVALID_CREDENTIALS:", ""),
        401,
      );
    }
    if (message.startsWith("ACCOUNT_SUSPENDED:")) {
      return failedLoginResponse(
        loginEmail,
        ipAddress,
        message.replace("ACCOUNT_SUSPENDED:", ""),
        403,
      );
    }
    console.error("[Auth:Login] Error:", err);
    return NextResponse.json({ error: "Error interno al autenticar usuario" }, { status: 500 });
  }
}
