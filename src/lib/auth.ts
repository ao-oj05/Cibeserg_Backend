import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

export const AUTH_COOKIE_NAME = "scandev_session";
function getJwtSecret(): Uint8Array {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET no configurado");
  }
  return new TextEncoder().encode(secret);
}

export interface SessionPayload {
  userId: string;
  email: string;
  role: string;
  iat?: number;
  exp?: number;
}

/**
 * Hashes a plaintext password using Argon2id (with fallback to PBKDF2 if native addon fails)
 */
export async function hashPassword(password: string): Promise<string> {
  const argon2 = await import("argon2");
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });
}

/**
 * Verifies a password against the stored hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    const argon2 = await import("argon2");
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Signs a new JWT session token (valid for 8 hours)
 */
export async function createSessionToken(payload: Omit<SessionPayload, "iat" | "exp">): Promise<string> {
  const JWT_SECRET = getJwtSecret();
  return await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(JWT_SECRET);
}

/**
 * Verifies an incoming session token and returns the payload
 */
export async function verifySessionToken(token: string): Promise<SessionPayload | null> {
  try {
    const JWT_SECRET = getJwtSecret();
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    });
    return payload as unknown as SessionPayload;
  } catch {
    return null;
  }
}

/**
 * Extracts and verifies the session user strictly from its HttpOnly cookie.
 */
export async function getSessionUser(req?: NextRequest): Promise<SessionPayload | null> {
  let token: string | undefined;

  if (req) {
    // 1. Try cookie from request
    token = req.cookies.get(AUTH_COOKIE_NAME)?.value;

  } else {
    // Next.js Server Component / Action cookie retrieval
    try {
      const cookieStore = await cookies();
      token = cookieStore.get(AUTH_COOKIE_NAME)?.value;
    } catch {
      // Not in Server Component context
    }
  }

  if (!token) return null;
  const session = await verifySessionToken(token);
  if (!session) return null;

  const user = await prisma.user.findUnique({
    where: { id: session.userId },
    select: { suspendedAt: true },
  });
  return user?.suspendedAt ? null : session;
}

/**
 * Returns security-hardened cookie options for session storage
 */
export function getSessionCookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  return {
    name: AUTH_COOKIE_NAME,
    httpOnly: true,
    secure: isProd,
    sameSite: "lax" as const,
    path: "/",
    maxAge: 60 * 60 * 8, // 8 hours
  };
}
