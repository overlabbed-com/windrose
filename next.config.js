/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  serverExternalPackages: ['@napi-rs/canvas', 'pdf-parse', 'officeparser', 'pdfjs-dist'],
};

export default nextConfig;