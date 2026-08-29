/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // Served behind the reverse proxy under /admin on the same origin as the
  // API; all router.push/link hrefs pick this up automatically.
  basePath: "/admin",
  // The API base URL is read at runtime via NEXT_PUBLIC_API_BASE_URL.
  reactStrictMode: true,
};
export default nextConfig;
