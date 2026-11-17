import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { NextRequest } from "next/server";
import crypto from "crypto";

export const AUTH_COOKIE_NAME = "scandev_session";
const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || "default_super_secret_jwt_key_minimum_32_characters_length"
);

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
  try {
    const argon2 = await import("argon2");
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
  } catch (err) {
    // Fallback: Node native crypto scrypt
    const salt = crypto.randomBytes(16).toString("hex");
    const derivedKey = crypto.scryptSync(password, salt, 64).toString("hex");
    return `scrypt:${salt}:${derivedKey}`;
  }
}

/**
 * Verifies a password against the stored hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    if (hash.startsWith("scrypt:")) {
      const [, salt, originalKey] = hash.split(":");
      const keyBuffer = Buffer.from(originalKey, "hex");
      const derivedKey = crypto.scryptSync(password, salt, 64);
      return crypto.timingSafeEqual(keyBuffer, derivedKey);
    }
    const argon2 = await import("argon2");
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Signs a new JWT session token (valid for 24 hours)
 */
export async function createSessionToken(payload: Omit<SessionPayload, "iat" | "exp">): Promise<string> {
  return await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(JWT_SECRET);
}

/**
 * Verifies an incoming session token and returns the payload
 */
export async function verifySessionToken(token: string): Promise<SessionPayload | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    });
    return payload as unknown as SessionPayload;
  } catch {
    return null;
  }
}

/**
 * Extracts and verifies the session user strictly from cookies or Authorization header (BK-04 & BK-05)
 */
export async function getSessionUser(req?: NextRequest): Promise<SessionPayload | null> {
  let token: string | undefined;

  if (req) {
    // 1. Try cookie from request
    token = req.cookies.get(AUTH_COOKIE_NAME)?.value;

    // 2. Try Bearer header if cookie is absent
    if (!token) {
      const authHeader = req.headers.get("authorization");
      if (authHeader?.startsWith("Bearer ")) {
        token = authHeader.substring(7);
      }
    }
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
  return await verifySessionToken(token);
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
    sameSite: "strict" as const,
    path: "/",
    maxAge: 60 * 60 * 24, // 24 hours
  };
}
