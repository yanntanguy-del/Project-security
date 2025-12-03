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
                Windows
              </a>
              
              <a
                href="/downloads/SecurityScanner.dmg"
                className="px-8 py-4 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-xl transition-all hover:scale-105 border border-gray-700 flex items-center justify-center gap-3"
              >
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
                </svg>
                macOS
              </a>

              <a
                href="/downloads/SecurityScanner.AppImage"
                className="px-8 py-4 bg-orange-700 hover:bg-orange-600 text-white font-bold rounded-xl transition-all hover:scale-105 border border-orange-600 flex items-center justify-center gap-3"
              >
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12.504 0c-.155 0-.315.008-.48.021-4.226.333-3.105 4.807-3.17 6.298-.076 1.092-.3 1.953-1.05 3.02-.885 1.051-2.127 2.75-2.716 4.521-.278.832-.41 1.684-.287 2.489a.424.424 0 00-.11.135c-.26.268-.45.6-.663.839-.199.199-.485.267-.797.4-.313.136-.658.269-.864.68-.09.189-.136.394-.132.602 0 .199.027.4.055.536.058.399.116.728.04.97-.249.68-.28 1.145-.106 1.484.174.334.535.47.94.601.81.2 1.91.135 2.774.6.926.466 1.866.67 2.616.47.526-.116.97-.464 1.208-.946.587-.003 1.23-.269 2.26-.334.699-.058 1.574.267 2.577.2.025.134.063.198.114.333l.003.003c.391.778 1.113 1.132 1.884 1.071.771-.06 1.592-.536 2.257-1.306.631-.765 1.683-1.084 2.378-1.503.348-.199.629-.469.649-.853.023-.4-.2-.811-.714-1.376v-.097l-.003-.003c-.17-.2-.25-.535-.338-.926-.085-.401-.182-.786-.492-1.046h-.003c-.059-.054-.123-.067-.188-.135a.357.357 0 00-.19-.064c.431-1.278.264-2.55-.173-3.694-.533-1.41-1.465-2.638-2.175-3.483-.796-1.005-1.576-1.957-1.56-3.368.026-2.152.236-6.133-3.544-6.139zm.529 3.405h.013c.213 0 .396.062.584.198.19.135.33.332.438.533.105.259.158.459.166.724 0-.02.006-.04.006-.06v.105a.086.086 0 01-.004-.021l-.004-.024a1.807 1.807 0 01-.15.706.953.953 0 01-.213.335.71.71 0 00-.088-.042c-.104-.045-.198-.064-.284-.133a1.312 1.312 0 00-.22-.066c.05-.06.146-.133.183-.198.053-.128.082-.264.088-.402v-.02a1.21 1.21 0 00-.061-.4c-.045-.134-.101-.2-.183-.333-.084-.066-.167-.132-.267-.132h-.016c-.093 0-.176.03-.262.132a.8.8 0 00-.205.334 1.18 1.18 0 00-.09.4v.019c.002.089.008.179.02.267-.193-.067-.438-.135-.607-.202a1.635 1.635 0 01-.018-.2v-.02a1.772 1.772 0 01.15-.768c.082-.22.232-.406.43-.533a.985.985 0 01.594-.2zm-2.962.059h.036c.142 0 .27.048.399.135.146.129.264.288.344.465.09.199.14.4.153.667v.004c.007.134.006.2-.002.266v.08c-.03.007-.056.018-.083.024-.152.055-.274.135-.393.2.012-.09.013-.18.003-.267v-.015c-.012-.133-.04-.2-.082-.333a.613.613 0 00-.166-.267.248.248 0 00-.183-.064h-.021c-.071.006-.13.04-.186.132a.552.552 0 00-.12.27.944.944 0 00-.023.33v.015c.012.135.037.2.08.334.046.134.098.2.166.268.01.009.02.018.034.024-.07.057-.117.07-.176.136a.304.304 0 01-.131.068 2.62 2.62 0 01-.275-.402 1.772 1.772 0 01-.155-.667 1.759 1.759 0 01.08-.668 1.43 1.43 0 01.283-.535c.128-.133.26-.2.418-.2zm1.37 1.706c.332 0 .733.065 1.216.399.293.2.523.269 1.052.468h.003c.255.136.405.266.478.399v-.131a.571.571 0 01.016.47c-.123.31-.516.643-1.063.842v.002c-.268.135-.501.333-.775.465-.276.135-.588.292-1.012.267a1.139 1.139 0 01-.448-.067 3.566 3.566 0 01-.322-.198c-.195-.135-.363-.332-.612-.465v-.005h-.005c-.4-.246-.616-.512-.686-.71-.07-.268-.005-.47.193-.6.224-.135.38-.271.483-.336.104-.074.143-.102.176-.131h.002v-.003c.169-.202.436-.47.839-.601.139-.036.294-.065.466-.065zm2.8 2.142c.358 1.417 1.196 3.475 1.735 4.473.286.534.855 1.659 1.102 3.024.156-.005.33.018.513.064.646-1.671-.546-3.467-1.089-3.966-.22-.2-.232-.335-.123-.335.59.534 1.365 1.572 1.646 2.757.13.535.16 1.104.021 1.67.067.028.135.06.205.067 1.032.534 1.413.938 1.23 1.537v-.002c-.06-.135-.12-.2-.18-.264-.064-.135-.142-.2-.209-.267a1.38 1.38 0 00-.116-.132c.404.266.688.668.855 1.07v.001a1.502 1.502 0 01-.103-.2c-.004-.003-.012-.01-.015-.013a.708.708 0 00-.14-.333.593.593 0 00-.036-.067 2.23 2.23 0 00-.142-.134h-.001c-.18-.2-.413-.266-.671-.266a1.681 1.681 0 00-.722.2c-.212.135-.395.266-.551.4-.156.133-.299.266-.427.398-.128.135-.247.266-.358.401-.2.267-.38.535-.546.802-.135.202-.27.4-.388.535-.155.266-.312.465-.505.664-.188.201-.41.4-.672.6-.26.2-.582.398-.963.463-.38.067-.82.002-1.257-.2-.436-.2-.866-.466-1.25-.865-.383-.4-.714-.867-.978-1.401a6.606 6.606 0 01-.618-1.87 7.467 7.467 0 01-.104-1.936c.037-.534.12-1.068.252-1.536.122-.468.3-.868.534-1.202-.173.065-.34.135-.504.2-.633.268-1.197.6-1.59.869-.392.266-.62.4-.72.533a.8.8 0 00-.04.06c-.04.134-.064.266-.064.4 0 .2.039.398.118.465.079.065.2.002.318-.133.12-.133.243-.336.365-.465.124-.135.246-.267.367-.267a.27.27 0 01.036 0 .54.54 0 01.068.135c.023.068.016.135-.009.201a.759.759 0 01-.212.334c-.149.133-.346.266-.542.4-.205.133-.408.266-.533.467a.88.88 0 00-.117.4c0 .068.01.138.028.2.014.068.037.135.067.2.024.067.063.133.1.2.04.066.077.133.117.2.267.398.684.734 1.132.936.448.2.925.27 1.304.135.38-.136.678-.467.873-.868.084-.2.138-.4.152-.6.016-.2-.008-.4-.066-.6-.027-.134-.064-.2-.09-.267-.005-.065-.01-.135-.01-.2 0-.133.014-.265.04-.398.026-.133.065-.265.107-.398.043-.133.092-.2.138-.332.05-.134.096-.2.142-.334.046-.133.088-.267.125-.4.038-.134.073-.2.1-.333.06-.199.105-.398.14-.598.038-.2.064-.398.078-.598a3.3 3.3 0 00-.035-.598 3.058 3.058 0 00-.122-.6 3.012 3.012 0 00-.199-.598 2.673 2.673 0 00-.277-.535 2.83 2.83 0 00-.339-.466 3.118 3.118 0 00-.394-.4 3.495 3.495 0 00-.437-.335 3.61 3.61 0 00-.478-.267c.34-.066.7-.067 1.05.065.349.135.68.335.973.6.293.267.552.6.763.932z"/>
                </svg>
                Linux
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
