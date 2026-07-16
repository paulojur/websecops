import type { NextConfig } from "next";

function parseAllowedDevOrigins() {
  const rawValue = process.env.NEXT_ALLOWED_DEV_ORIGINS?.trim();

  if (!rawValue) {
    return [];
  }

  return rawValue
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

const nextConfig: NextConfig = {
  output: "standalone",
  allowedDevOrigins: parseAllowedDevOrigins(),
  async rewrites() {
    const backendUrl = process.env.BACKEND_INTERNAL_URL || "http://backend:8000";

    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendUrl}/api/v1/:path*`,
      },
    ];
  },
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
