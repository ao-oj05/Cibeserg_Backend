import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ["argon2", "pdfkit", "pg", "@prisma/adapter-pg"],
};

export default nextConfig;
