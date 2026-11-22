interface RateLimitRecord {
  timestamps: number[];
  windowMs: number;
}

const rateLimitStore = new Map<string, RateLimitRecord>();

// Clean up old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    record.timestamps = record.timestamps.filter((ts) => now - ts < record.windowMs);
    if (record.timestamps.length === 0) {
      rateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref?.();

export interface RateLimitOptions {
  limit?: number; // max requests
  windowMs?: number; // window size in ms
}

/**
 * Checks if a key (IP or userId) exceeds rate limits (BK-02)
 */
export function checkRateLimit(
  key: string,
  options: RateLimitOptions = {}
): { success: boolean; remaining: number; resetMs: number } {
  const limit = options.limit ?? 10;
  const windowMs = options.windowMs ?? 60_000;
  const now = Date.now();

  let record = rateLimitStore.get(key);
  if (!record) {
    record = { timestamps: [], windowMs };
    rateLimitStore.set(key, record);
  }

  record.windowMs = windowMs;
  // Filter timestamps within current window
  record.timestamps = record.timestamps.filter((ts) => now - ts < windowMs);

  if (record.timestamps.length >= limit) {
    const oldestTimestamp = record.timestamps[0];
    const resetMs = Math.max(0, windowMs - (now - oldestTimestamp));
    return {
      success: false,
      remaining: 0,
      resetMs,
    };
  }

  record.timestamps.push(now);
  return {
    success: true,
    remaining: limit - record.timestamps.length,
    resetMs: windowMs,
  };
}
