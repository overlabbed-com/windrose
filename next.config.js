/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals = config.externals || [];
      config.externals.push(
        '@huggingface/transformers', 
        'onnxruntime-node', 
        'playwright', 
        'jsdom',
        '@napi-rs/canvas',
        'pdf-parse',
        'pdf-parse/worker',
        'officeparser',
        'pdfjs-dist',
        'yahoo-finance2',
        'yahoo-finance2/esm',
        '@gadicc/fetch-mock-cache'
      );
    }
    return config;
  },
};

export default nextConfig;
