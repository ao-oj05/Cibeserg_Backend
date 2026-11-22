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

export interface RateLimitResult {
  success: boolean;
  remaining: number;
  resetMs: number;
}

function getOptions(options: RateLimitOptions) {
  return {
    limit: options.limit ?? 10,
    windowMs: options.windowMs ?? 60_000,
  };
}

export function getRateLimitStatus(
  key: string,
  options: RateLimitOptions = {},
): RateLimitResult {
  const { limit, windowMs } = getOptions(options);
  const now = Date.now();
  const record = rateLimitStore.get(key);
  if (!record) return { success: true, remaining: limit, resetMs: windowMs };

  record.windowMs = windowMs;
  record.timestamps = record.timestamps.filter((ts) => now - ts < windowMs);
  if (record.timestamps.length === 0) {
    rateLimitStore.delete(key);
    return { success: true, remaining: limit, resetMs: windowMs };
  }

  if (record.timestamps.length >= limit) {
    return {
      success: false,
      remaining: 0,
      resetMs: Math.max(0, windowMs - (now - record.timestamps[0])),
    };
  }

  return {
    success: true,
    remaining: limit - record.timestamps.length,
    resetMs: Math.max(0, windowMs - (now - record.timestamps[0])),
  };
}

export function recordRateLimitHit(
  key: string,
  options: RateLimitOptions = {},
): RateLimitResult {
  const { limit, windowMs } = getOptions(options);
  const status = getRateLimitStatus(key, options);
  if (!status.success) return status;

  const now = Date.now();
  let record = rateLimitStore.get(key);
  if (!record) {
    record = { timestamps: [], windowMs };
    rateLimitStore.set(key, record);
  }
  record.windowMs = windowMs;
  record.timestamps.push(now);

  return {
    success: true,
    remaining: Math.max(0, limit - record.timestamps.length),
    resetMs: windowMs,
  };
}

/**
 * Checks if a key (IP or userId) exceeds rate limits (BK-02)
 */
export function checkRateLimit(
  key: string,
  options: RateLimitOptions = {},
): RateLimitResult {
  const status = getRateLimitStatus(key, options);
  return status.success ? recordRateLimitHit(key, options) : status;
}
