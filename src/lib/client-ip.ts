import { isIP } from "node:net";
import type { NextRequest } from "next/server";
import { env } from "./env";

export function getClientIp(req: Pick<NextRequest, "headers">): string | null {
  if (env.NODE_ENV !== "production" && env.TRUSTED_PROXY_HOPS === 0) {
    return "127.0.0.1";
  }
  if (env.TRUSTED_PROXY_HOPS < 1) return null;

  const forwardedFor = req.headers.get("x-forwarded-for");
  if (!forwardedFor) {
    return env.NODE_ENV === "production" ? null : "127.0.0.1";
  }

  const addresses = forwardedFor.split(",").map((address) => address.trim());
  const clientAddressIndex = addresses.length - env.TRUSTED_PROXY_HOPS;
  if (clientAddressIndex < 0) return null;

  const clientAddress = addresses[clientAddressIndex];
  return clientAddress && isIP(clientAddress) ? clientAddress : null;
}
