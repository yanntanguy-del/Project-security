"use client";

import { useEffect, useState } from "react";

// URL de votre API Vercel (sera automatiquement la bonne en production)
const LICENSE_API = "/api/license";

export function ExpirationGuard({ children }: { children: React.ReactNode }) {
  const [isValid, setIsValid] = useState<boolean | null>(null);

  useEffect(() => {
    async function checkLicense() {
      try {
        const res = await fetch(LICENSE_API, { cache: "no-store" });
        const data = await res.json();
        setIsValid(data.valid === true);
      } catch {
        // Si pas de connexion internet, bloquer l'app
        setIsValid(false);
      }
    }
    checkLicense();
  }, []);

  // Chargement
  if (isValid === null) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500 mx-auto mb-4"></div>
          <p className="text-slate-500 text-sm">Vérification...</p>
        </div>
      </div>
    );
  }

  // App désactivée
  if (!isValid) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
        <div className="text-center">
          <div className="w-20 h-20 mx-auto mb-6 rounded-full bg-slate-800 flex items-center justify-center">
            <svg className="w-10 h-10 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-slate-400 mb-2">Service temporairement indisponible</h1>
          <p className="text-slate-600 text-sm">Veuillez réessayer plus tard.</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
