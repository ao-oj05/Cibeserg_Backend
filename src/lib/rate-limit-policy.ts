export interface RateLimitResult {
  success: boolean;
  remaining: number;
  resetMs: number;
}

export function calculateRateLimit(
  timestamps: Date[],
  now: number,
  limit: number,
  windowMs: number,
): RateLimitResult {
  const activeHits = timestamps.filter((timestamp) => now - timestamp.getTime() < windowMs);
  const firstHit = activeHits.reduce<number | undefined>(
    (oldest, timestamp) => Math.min(oldest ?? timestamp.getTime(), timestamp.getTime()),
    undefined,
  );
  const resetMs = firstHit === undefined
    ? windowMs
    : Math.max(0, windowMs - (now - firstHit));

  if (activeHits.length >= limit) {
    return { success: false, remaining: 0, resetMs };
  }

  return {
    success: true,
    remaining: limit - activeHits.length,
    resetMs,
  };
}
