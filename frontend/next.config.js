/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',        // static export — works for both FastAPI (local) and Cloudflare Pages
  trailingSlash: true,     // /dashboard → /dashboard/index.html
  images: {
    unoptimized: true,     // required for static export (no Next.js image server)
  },
};

module.exports = nextConfig;
