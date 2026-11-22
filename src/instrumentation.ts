import { env } from "./lib/env";

export function register(): void {
  if (!env.DATABASE_URL || !env.JWT_SECRET) {
    throw new Error("Faltan variables de entorno obligatorias");
  }
}
