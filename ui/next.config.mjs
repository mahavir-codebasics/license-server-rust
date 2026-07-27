/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // The API base URL is read at runtime via NEXT_PUBLIC_API_BASE_URL.
  reactStrictMode: true,
};
export default nextConfig;
