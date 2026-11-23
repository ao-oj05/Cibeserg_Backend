import { createHmac } from "node:crypto";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { calculateRateLimit, type RateLimitResult } from "./rate-limit-policy";

const MAX_RATE_LIMIT_WINDOW_MS = 60 * 60_000;
const CLEANUP_INTERVAL_MS = 60_000;
let lastCleanupAt = 0;

export interface RateLimitOptions {
  limit?: number;
  windowMs?: number;
}

function getOptions(options: RateLimitOptions) {
  return {
    limit: options.limit ?? 10,
    windowMs: options.windowMs ?? 60_000,
  };
}

function digestKey(key: string): string {
  return createHmac("sha256", env.JWT_SECRET).update(key).digest("hex");
}

async function withRateLimitHits<T>(
  key: string,
  windowMs: number,
  operation: (timestamps: Date[], now: number, recordHit: () => Promise<Date>) => Promise<T>,
): Promise<T> {
  const keyDigest = digestKey(key);
  return prisma.$transaction(async (transaction) => {
    await transaction.$queryRaw`
      SELECT 1
      FROM (SELECT pg_advisory_xact_lock(hashtextextended(${keyDigest}, 0))) AS lock_result
    `;

    const now = Date.now();
    if (now - lastCleanupAt >= CLEANUP_INTERVAL_MS) {
      lastCleanupAt = now;
      try {
        await transaction.rateLimitHit.deleteMany({
          where: { createdAt: { lt: new Date(now - MAX_RATE_LIMIT_WINDOW_MS) } },
        });
      } catch (error) {
        lastCleanupAt = 0;
        throw error;
      }
    }

    const hits = await transaction.rateLimitHit.findMany({
      where: {
        keyDigest,
        createdAt: { gt: new Date(now - windowMs) },
      },
      orderBy: { createdAt: "asc" },
      select: { createdAt: true },
    });

    return operation(
      hits.map((hit) => hit.createdAt),
      now,
      async () => {
        const hit = await transaction.rateLimitHit.create({
          data: { keyDigest },
          select: { createdAt: true },
        });
        return hit.createdAt;
      },
    );
  });
}

export function getRateLimitStatus(
  key: string,
  options: RateLimitOptions = {},
): Promise<RateLimitResult> {
  const { limit, windowMs } = getOptions(options);
  return withRateLimitHits(key, windowMs, async (timestamps, now) =>
    calculateRateLimit(timestamps, now, limit, windowMs),
  );
}

export function recordRateLimitHit(
  key: string,
  options: RateLimitOptions = {},
): Promise<RateLimitResult> {
  const { limit, windowMs } = getOptions(options);
  return withRateLimitHits(key, windowMs, async (timestamps, now, addHit) => {
    const current = calculateRateLimit(timestamps, now, limit, windowMs);
    if (!current.success) return current;

    timestamps.push(await addHit());
    return calculateRateLimit(timestamps, Date.now(), limit, windowMs);
  });
}

export function checkRateLimit(
  key: string,
  options: RateLimitOptions = {},
): Promise<RateLimitResult> {
  return recordRateLimitHit(key, options);
}
