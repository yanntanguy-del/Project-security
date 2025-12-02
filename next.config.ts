import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  // Note: "output: export" est désactivé car nous utilisons des API routes dynamiques
  // qui exécutent PowerShell pour la détection système
  images: {
    unoptimized: true
  },
  // ==========================================
  // PROTECTION DU CODE SOURCE
  // ==========================================
  productionBrowserSourceMaps: false, // Pas de source maps en production
  compiler: {
    removeConsole: true, // Supprime tous les console.log en production
  },
  // Ignorer les erreurs pour le build Vercel
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  // Headers de sécurité
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-XSS-Protection", value: "1; mode=block" },
        ],
      },
    ];
  },
  webpack: (config, { isServer }) => {
    if (!isServer) {
      // Désactive les source maps côté client
      config.devtool = false;
      // Minification maximale
      config.optimization = {
        ...config.optimization,
        minimize: true,
      };
    }
    return config;
  }
};

export default nextConfig;
