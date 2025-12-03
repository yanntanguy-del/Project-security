"use client";

import { useState, useEffect } from "react";

// Date d'expiration - 30 décembre 2025
const EXPIRATION_DATE = new Date("2025-12-30T00:00:00");

// Vérifier si l'app est expirée
const isExpired = () => {
  return new Date() >= EXPIRATION_DATE;
};

// Détecter si on est dans Electron (local) ou sur le web (Vercel)
const isElectron = () => {
  if (typeof window === "undefined") return false;
  return !!(window as any).electron || navigator.userAgent.includes("Electron");
};

// ============================================================================
// PAGE DE TÉLÉCHARGEMENT (VERCEL)
// ============================================================================
function DownloadPage() {
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    setExpired(isExpired());
  }, []);

  // Si expiré, afficher une page vide/erreur
  if (expired) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center">
          <p className="text-gray-500">Service temporairement indisponible</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-violet-950/40 via-black to-purple-950/30 pointer-events-none" />
      
      <div className="relative min-h-screen flex flex-col">
        {/* Header */}
        <header className="border-b border-violet-500/20 bg-black/50 backdrop-blur-sm">
          <div className="container mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-2xl">🛡️</span>
              <span className="text-xl font-bold text-violet-400">Security Scanner</span>
            </div>
            <span className="text-xs text-gray-500">v0.1.0</span>
          </div>
        </header>

        {/* Hero Section */}
        <main className="flex-1 flex items-center justify-center px-6 py-12">
          <div className="max-w-4xl mx-auto text-center">
            {/* Icon */}
            <div className="mb-8">
              <span className="text-8xl">🛡️</span>
            </div>

            {/* Title */}
            <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-violet-400 to-purple-400 bg-clip-text text-transparent">
              Security Scanner
            </h1>

            {/* Subtitle */}
            <p className="text-xl text-gray-400 mb-4 max-w-2xl mx-auto">
              Analysez la sécurité de votre ordinateur en quelques clics.
              Basé sur les recommandations Microsoft Security Baselines & CIS Benchmarks.
            </p>

            <p className="text-gray-500 mb-12">
              Compatible Windows 10/11, macOS et Linux
            </p>

            {/* Download Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
              <a
                href="/downloads/SecurityScanner-Setup.exe"
                className="px-8 py-4 bg-violet-600 hover:bg-violet-500 text-white font-bold rounded-xl transition-all hover:scale-105 shadow-lg shadow-violet-500/25 flex items-center justify-center gap-3"
              >
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
                </svg>
                Télécharger pour Windows
              </a>
              
              <a
                href="/downloads/SecurityScanner.dmg"
                className="px-8 py-4 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-xl transition-all hover:scale-105 border border-gray-700 flex items-center justify-center gap-3"
              >
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
                </svg>
                Télécharger pour macOS
              </a>
            </div>

            {/* Features */}
            <div className="grid md:grid-cols-3 gap-6 text-left max-w-3xl mx-auto">
              <div className="p-6 rounded-xl bg-violet-900/20 border border-violet-500/30">
                <div className="text-3xl mb-3">🔍</div>
                <h3 className="font-bold text-white mb-2">Analyse complète</h3>
                <p className="text-sm text-gray-400">
                  Vérifie plus de 100 paramètres de sécurité sur votre système
                </p>
              </div>
              
              <div className="p-6 rounded-xl bg-violet-900/20 border border-violet-500/30">
                <div className="text-3xl mb-3">📊</div>
                <h3 className="font-bold text-white mb-2">Rapport détaillé</h3>
                <p className="text-sm text-gray-400">
                  Explications claires et solutions pour chaque problème détecté
                </p>
              </div>
              
              <div className="p-6 rounded-xl bg-violet-900/20 border border-violet-500/30">
                <div className="text-3xl mb-3">🔒</div>
                <h3 className="font-bold text-white mb-2">100% local</h3>
                <p className="text-sm text-gray-400">
                  Toutes les analyses sont effectuées localement sur votre machine
                </p>
              </div>
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer className="border-t border-violet-500/20 py-6">
          <div className="container mx-auto px-6 text-center text-sm text-gray-500">
            <p>© 2025 Security Scanner. Tous droits réservés.</p>
          </div>
        </footer>
      </div>
    </div>
  );
}

// ============================================================================
// SCANNER (ELECTRON)
// ============================================================================

interface Finding {
  id: string;
  name: string;
  category: string;
  method: string;
  recommendedValue?: string;
  currentValue?: string;
  status: "pass" | "fail" | "unknown";
  severity: string;
  description?: string;
  risk?: string;
  compatibility?: string;
  skipReason?: string;
  defaultValue?: string;
  remediation?: string | {
    default?: string;
    gpo?: string;
    intune?: string;
    manual?: string;
  };
}

interface ScanResult {
  system: {
    osFamily: string;
    osName: string;
    osVersion: string;
    osEdition: string;
    buildNumber: string;
    manufacturer: string;
    model: string;
  };
  baseline: string;
  totalFindings: number;
  findings: Finding[];
}

// Dictionnaire de traduction des noms de paramètres
const translations: Record<string, string> = {
  "Account lockout duration": "Durée de verrouillage du compte",
  "Account lockout threshold": "Seuil de verrouillage du compte",
  "Allow Administrator account lockout": "Autoriser le verrouillage du compte Administrateur",
  "Length of password history maintained": "Historique des mots de passe conservés",
  "Minimum password length": "Longueur minimale du mot de passe",
  "Password must meet complexity requirements": "Complexité du mot de passe requise",
  "Store passwords using reversible encryption": "Stocker les mots de passe de façon réversible",
  "Accounts: Limit local account use of blank passwords to console logon only": "Limiter les mots de passe vides aux connexions locales",
  "Interactive logon: Machine inactivity limit": "Verrouillage automatique après inactivité",
  "Microsoft network client: Digitally sign communications (always)": "Signature numérique des communications réseau",
  "Network security: Do not store LAN Manager hash value": "Ne pas stocker le hash LAN Manager",
  "Network security: LAN Manager authentication level": "Niveau d'authentification LAN Manager",
  "User Account Control: Admin Approval Mode for Built-in Administrator": "UAC : Mode d'approbation pour Administrateur intégré",
  "User Account Control: Behavior of elevation prompt for administrators": "UAC : Comportement de l'invite d'élévation",
  "User Account Control: Run all administrators in Admin Approval Mode": "UAC : Mode d'approbation pour tous les admins",
  "EnableFirewall (Domain Profile)": "Pare-feu activé (Profil Domaine)",
  "EnableFirewall (Private Profile)": "Pare-feu activé (Profil Privé)",
  "EnableFirewall (Public Profile)": "Pare-feu activé (Profil Public)",
  "Configure SMB v1 client driver": "Désactiver SMBv1 (client)",
  "Configure SMB v1 server": "Désactiver SMBv1 (serveur)",
  "WDigest Authentication": "Authentification WDigest désactivée",
  "Turn on behavior monitoring": "Surveillance du comportement",
  "Turn on real-time protection": "Protection en temps réel",
  "Dell SupportAssist Service": "Service Dell SupportAssist",
  "Dell Data Vault Collector": "Collecteur de données Dell",
};

const translateName = (name: string): string => translations[name] || name;

const translateCategory = (category: string): string => {
  const categoryTranslations: Record<string, string> = {
    "Account Policies": "Stratégies de compte",
    "Security Options": "Options de sécurité",
    "Windows Firewall": "Pare-feu Windows",
    "MS Security Guide": "Guide de sécurité Microsoft",
    "Windows Defender": "Windows Defender",
    "Windows Defender Antivirus": "Antivirus Windows Defender",
    "BitLocker": "BitLocker",
    "Attack Surface Reduction": "Réduction de la surface d'attaque",
    "Remote Desktop": "Bureau à distance",
    "Audit": "Audit",
    "Services": "Services",
    "Privacy": "Confidentialité",
    "System": "Système",
    "Network": "Réseau",
    "OEM - Dell": "Fabricant - Dell",
    "OEM - HP": "Fabricant - HP",
    "OEM - Lenovo": "Fabricant - Lenovo",
    "Filesystem Configuration": "Configuration du système de fichiers",
  };
  return categoryTranslations[category] || category;
};

const translateSeverity = (severity: string): string => {
  const severityTranslations: Record<string, string> = {
    "Critical": "Critique",
    "High": "Élevé",
    "Medium": "Moyen",
    "Low": "Faible",
  };
  return severityTranslations[severity] || severity;
};

function ScannerPage() {
  const [loading, setLoading] = useState(true);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "pass" | "fail" | "unknown">("all");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    if (isExpired()) {
      setExpired(true);
      setLoading(false);
      return;
    }
    runScan();
  }, []);

  const runScan = async () => {
    if (isExpired()) {
      setExpired(true);
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (!res.ok) throw new Error("Erreur lors de l'analyse");
      const data = await res.json();
      setScanResult(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Erreur inconnue");
    } finally {
      setLoading(false);
    }
  };

  // Si expiré, afficher une page vide
  if (expired) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center">
          <p className="text-gray-500">Application non disponible</p>
        </div>
      </div>
    );
  }

  const visibleFindings = scanResult?.findings || [];
  const filteredFindings = visibleFindings.filter((f) => filter === "all" || f.status === filter);
  const passCount = visibleFindings.filter(f => f.status === "pass").length;
  const failCount = visibleFindings.filter(f => f.status === "fail").length;
  const unknownCount = visibleFindings.filter(f => f.status === "unknown").length;

  const getUnknownReason = (finding: Finding): { reason: string; solution: string; icon: string } => {
    if (finding.skipReason) {
      switch (finding.skipReason) {
        case "edition_incompatible":
          return { reason: "Cette fonctionnalité n'est pas disponible sur votre version de Windows (Home)", solution: "Nécessite Windows Pro ou Enterprise.", icon: "🏠" };
        case "admin_required":
          return { reason: "Droits administrateur requis", solution: "Exécutez l'application en tant qu'administrateur.", icon: "🔐" };
        case "manual_check":
          return { reason: "Vérification manuelle requise", solution: "Vérifiez ce paramètre vous-même.", icon: "👤" };
      }
    }
    if (finding.currentValue?.includes("Non configuré")) {
      return { reason: "Paramètre non configuré", solution: "Windows utilise la valeur par défaut.", icon: "⚠️" };
    }
    return { reason: "Valeur non déterminée", solution: "Relancez le scan ou vérifiez manuellement.", icon: "❓" };
  };

  return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 bg-gradient-to-br from-violet-950/40 via-black to-purple-950/30 pointer-events-none" />
      
      <header className="relative border-b border-violet-500/20 bg-black/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold text-violet-400">Security Scanner</span>
          </div>
          <button
            onClick={runScan}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white font-medium transition disabled:opacity-50"
          >
            {loading ? "⏳ Analyse..." : "🔄 Nouvelle analyse"}
          </button>
        </div>
      </header>

      <main className="relative container mx-auto px-6 py-8">
        {loading && (
          <div className="flex flex-col items-center justify-center py-20">
            <div className="w-16 h-16 border-4 border-violet-500/30 border-t-violet-500 rounded-full animate-spin mb-4" />
            <p className="text-gray-400">Analyse de sécurité en cours...</p>
          </div>
        )}

        {error && !loading && (
          <div className="text-center py-20">
            <p className="text-red-400 mb-4">❌ {error}</p>
            <button onClick={runScan} className="px-6 py-2 rounded-lg bg-violet-600 hover:bg-violet-500">Réessayer</button>
          </div>
        )}

        {scanResult && !loading && (
          <>
            <div className="mb-6 p-4 rounded-xl bg-violet-900/20 border border-violet-500/30">
              <div className="grid md:grid-cols-4 gap-4 text-sm">
                <div><span className="text-gray-400">Système : </span><span className="text-white font-medium">{scanResult.system.osName}</span></div>
                <div><span className="text-gray-400">Édition : </span><span className="text-white font-medium">{scanResult.system.osEdition || "N/A"}</span></div>
                <div><span className="text-gray-400">Machine : </span><span className="text-white font-medium">{scanResult.system.manufacturer} {scanResult.system.model}</span></div>
                <div><span className="text-gray-400">Baseline : </span><span className="text-violet-400 font-medium">{scanResult.baseline}</span></div>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
              <div className="p-4 rounded-xl bg-violet-900/20 border border-violet-500/30">
                <p className="text-gray-400 text-sm">Total</p>
                <p className="text-2xl font-bold text-white">{visibleFindings.length}</p>
              </div>
              <div className="p-4 rounded-xl bg-green-900/20 border border-green-500/30">
                <p className="text-gray-400 text-sm">Conformes</p>
                <p className="text-2xl font-bold text-green-400">{passCount}</p>
              </div>
              <div className="p-4 rounded-xl bg-red-900/20 border border-red-500/30">
                <p className="text-gray-400 text-sm">Non conformes</p>
                <p className="text-2xl font-bold text-red-400">{failCount}</p>
              </div>
              <div className="p-4 rounded-xl bg-yellow-900/20 border border-yellow-500/30">
                <p className="text-gray-400 text-sm">Non vérifiés</p>
                <p className="text-2xl font-bold text-yellow-400">{unknownCount}</p>
              </div>
            </div>

            <div className="flex gap-2 mb-6 flex-wrap">
              {[
                { key: "all", label: "Tous", count: visibleFindings.length },
                { key: "pass", label: "✓ Conformes", count: passCount },
                { key: "fail", label: "✗ Non conformes", count: failCount },
                { key: "unknown", label: "? Non vérifiés", count: unknownCount },
              ].map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setFilter(tab.key as typeof filter)}
                  className={`px-4 py-2 rounded-lg font-medium transition ${filter === tab.key ? "bg-violet-600 text-white" : "bg-violet-900/30 text-gray-400 hover:bg-violet-900/50"}`}
                >
                  {tab.label} ({tab.count})
                </button>
              ))}
            </div>

            <div className="space-y-3">
              {filteredFindings.map((finding) => (
                <div
                  key={finding.id}
                  className={`rounded-xl border transition-all ${finding.status === "pass" ? "bg-green-900/10 border-green-500/30" : finding.status === "fail" ? "bg-red-900/10 border-red-500/30" : "bg-yellow-900/10 border-yellow-500/30"}`}
                >
                  <button
                    onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
                    className="w-full p-4 flex items-center gap-4 text-left"
                  >
                    <span className={`text-xl ${finding.status === "pass" ? "text-green-400" : finding.status === "fail" ? "text-red-400" : "text-yellow-400"}`}>
                      {finding.status === "pass" ? "✓" : finding.status === "fail" ? "✗" : "?"}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-xs font-mono text-gray-500">{finding.id}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${finding.severity === "Critical" ? "bg-red-500/20 text-red-400" : finding.severity === "High" ? "bg-orange-500/20 text-orange-400" : finding.severity === "Medium" ? "bg-yellow-500/20 text-yellow-400" : "bg-blue-500/20 text-blue-400"}`}>
                          {translateSeverity(finding.severity || "Medium")}
                        </span>
                        <span className="text-xs text-gray-600">{translateCategory(finding.category)}</span>
                      </div>
                      <p className="font-medium text-white truncate">{translateName(finding.name || "Sans nom")}</p>
                    </div>
                    <span className={`text-gray-500 transition-transform ${expandedFinding === finding.id ? "rotate-180" : ""}`}>▼</span>
                  </button>

                  {expandedFinding === finding.id && (
                    <div className="px-4 pb-4 pt-0 border-t border-white/10 mt-2">
                      {finding.status === "unknown" && (
                        <div className="mt-4 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                          <p className="text-xs text-yellow-400 mb-2 font-semibold">{getUnknownReason(finding).icon} Pourquoi ?</p>
                          <p className="text-sm text-gray-300"><strong>Raison :</strong> {getUnknownReason(finding).reason}</p>
                          <p className="text-sm text-gray-300"><strong>Solution :</strong> {getUnknownReason(finding).solution}</p>
                        </div>
                      )}
                      {finding.description && (
                        <div className="mt-4 p-3 rounded-lg bg-blue-500/10 border border-blue-500/30">
                          <p className="text-xs text-blue-400 mb-2 font-semibold">💡 C'est quoi ?</p>
                          <p className="text-sm text-gray-300">{finding.description}</p>
                        </div>
                      )}
                      {finding.status === "fail" && finding.risk && (
                        <div className="mt-4 p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
                          <p className="text-xs text-orange-400 mb-2 font-semibold">⚠️ Risque</p>
                          <p className="text-sm text-gray-300">{finding.risk}</p>
                        </div>
                      )}
                      <div className="grid md:grid-cols-2 gap-4 mt-4">
                        <div className="p-3 rounded-lg bg-green-500/10">
                          <p className="text-xs text-green-400 mb-1">✓ Valeur recommandée</p>
                          <code className="text-sm text-white">{finding.recommendedValue ?? "N/A"}</code>
                        </div>
                        <div className={`p-3 rounded-lg ${finding.status === "pass" ? "bg-green-500/10" : finding.status === "unknown" ? "bg-yellow-500/10" : "bg-red-500/10"}`}>
                          <p className={`text-xs mb-1 ${finding.status === "pass" ? "text-green-400" : finding.status === "unknown" ? "text-yellow-400" : "text-red-400"}`}>
                            {finding.status === "pass" ? "✓" : finding.status === "unknown" ? "?" : "✗"} Valeur actuelle
                          </p>
                          <code className="text-sm text-white">{finding.currentValue ?? "Non définie"}</code>
                        </div>
                      </div>
                      {finding.remediation && finding.status === "fail" && (
                        <div className="mt-4 p-3 rounded-lg bg-violet-500/10 border border-violet-500/30">
                          <p className="text-xs text-violet-400 mb-3 font-semibold">🔧 Comment corriger ?</p>
                          {typeof finding.remediation === "string" ? (
                            <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono bg-black/30 p-2 rounded">{finding.remediation}</pre>
                          ) : (
                            <div className="space-y-3">
                              {finding.remediation.default && (
                                <div>
                                  <p className="text-xs text-gray-500 mb-1">💻 Commande PowerShell :</p>
                                  <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono bg-black/30 p-2 rounded">{finding.remediation.default}</pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                      <p className="mt-3 text-xs text-gray-500">Méthode: {finding.method || "N/A"} • Catégorie: {translateCategory(finding.category) || "N/A"}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </main>
    </div>
  );
}

// ============================================================================
// COMPOSANT PRINCIPAL
// ============================================================================
export default function HomePage() {
  const [isClient, setIsClient] = useState(false);
  const [isElectronApp, setIsElectronApp] = useState(false);

  useEffect(() => {
    setIsClient(true);
    setIsElectronApp(isElectron());
  }, []);

  // Pendant le SSR ou le chargement initial
  if (!isClient) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="w-16 h-16 border-4 border-violet-500/30 border-t-violet-500 rounded-full animate-spin" />
      </div>
    );
  }

  // Si on est dans Electron, afficher le scanner
  if (isElectronApp) {
    return <ScannerPage />;
  }

  // Sinon (Vercel), afficher la page de téléchargement
  return <DownloadPage />;
}
