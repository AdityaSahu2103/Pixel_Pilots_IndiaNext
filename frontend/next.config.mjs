/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl}/api/:path*`,
        // Disable proxy timeout natively to let python handle it
        basePath: false,
      },
    ];
  },
  experimental: {
    proxyTimeout: 120000,
  },
  transpilePackages: ['three'],
};

export default nextConfig;
