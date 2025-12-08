"use client";

import { useEffect, useState } from "react";

const EXPIRATION_DATE = new Date("2025-12-30T23:59:59");

export default function ExpirationGuard({ children }: { children: React.ReactNode }) {
  const [isExpired, setIsExpired] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkExpiration = () => {
      const now = new Date();
      setIsExpired(now > EXPIRATION_DATE);
      setIsLoading(false);
    };

    checkExpiration();
    // Vérifier toutes les minutes
    const interval = setInterval(checkExpiration, 60000);
    return () => clearInterval(interval);
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-white">Chargement...</div>
      </div>
    );
  }

  if (isExpired) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
        <div className="bg-red-900/50 border border-red-500 rounded-lg p-8 max-w-md text-center">
          <div className="text-6xl mb-4">⛔</div>
          <h1 className="text-2xl font-bold text-red-400 mb-4">
            Version expirée
          </h1>
          <p className="text-gray-300 mb-4">
            Cette version de démonstration a expiré le 30 décembre 2025.
          </p>
          <p className="text-gray-400 text-sm">
            Veuillez contacter l&apos;administrateur pour obtenir une nouvelle version.
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
