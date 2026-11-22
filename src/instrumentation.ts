import { env } from "./lib/env";

export async function register(): Promise<void> {
  if (!env.DATABASE_URL || !env.JWT_SECRET) {
    throw new Error("Faltan variables de entorno obligatorias");
  }
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { startScanWorker } = await import("./services/scan-queue");
    startScanWorker();
  }
}
