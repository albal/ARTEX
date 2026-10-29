import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` produces a purely static directory in web/out that can be dropped straight into
// an nginx web root. Development (next dev) does not set this variable, keeping the /api reverse proxy and hot reload.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site runs on mocks with no backend, so no /api reverse proxy is needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Stop a lockfile in a parent directory affecting root inference and asset path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // Allow dev resources (HMR) to be accessed from LAN IPs; add or remove as needed.
  // During development, allow any IPv4 origin to access /_next/* and HMR (unaffected by LAN IP changes).
  // Note: Next forbids a bare "*" for security, so a segmented wildcard is needed; "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Purely static export: no Node runtime; images are not optimised; each route produces <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend, no /api reverse proxy needed.
          images: { unoptimized: true },
        }
      : {
          // Development: reverse-proxy /api/* to the Go backend (default :8787, overridable with AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

export default nextConfig;
