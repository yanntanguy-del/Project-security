// app/page.tsx - Interface principale avec style violet original
"use client";

import { useState } from "react";

const APP_VERSION = "0.1.0";

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

interface SystemInfo {
  osFamily: string;
  osName: string;
  osVersion: string;
  osEdition?: string;
  buildNumber?: string;
  manufacturer?: string;
  model?: string;
}

interface ScanResult {
  system: SystemInfo;
  baseline: string;
  totalFindings: number;
  findings: Finding[];
  scannedAt: string;
}

type AppState = "welcome" | "scanning" | "results";

// Fonction pour expliquer pourquoi une analyse n'a pas pu être faite
const getUnknownReason = (finding: Finding): { reason: string; solution: string; icon: string } => {
  if (finding.skipReason) {
    switch (finding.skipReason) {
      case "edition_incompatible":
        return {
          reason: "Cette fonctionnalité n'est pas disponible sur votre version de Windows (Home)",
          solution: "Cette protection n'est disponible que sur Windows Pro ou Enterprise.",
          icon: "🏠"
        };
      case "admin_required":
        return {
          reason: "Ce paramètre nécessite des droits administrateur pour être lu",
          solution: "Exécutez l'application en tant qu'administrateur.",
          icon: "🔐"
        };
      case "manual_check":
        return {
          reason: "Cette vérification doit être faite manuellement",
          solution: "Vérifiez ce paramètre vous-même dans les paramètres Windows.",
          icon: "👤"
        };
    }
  }
  return {
    reason: "La valeur n'a pas pu être déterminée",
    solution: "Essayez de relancer le scan ou vérifiez manuellement",
    icon: "❓"
  };
};

export default function HomePage() {
  const [appState, setAppState] = useState<AppState>("welcome");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "pass" | "fail" | "unknown">("all");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const startScan = async () => {
    setAppState("scanning");
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
      setAppState("results");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Erreur inconnue");
      setAppState("welcome");
    }
  };

  const resetScan = () => {
    setAppState("welcome");
    setScanResult(null);
    setFilter("all");
    setExpandedFinding(null);
  };

  const visibleFindings = scanResult?.findings || [];
  const filteredFindings = visibleFindings.filter((f) => filter === "all" || f.status === filter);
  const passCount = visibleFindings.filter(f => f.status === "pass").length;
  const failCount = visibleFindings.filter(f => f.status === "fail").length;
  const unknownCount = visibleFindings.filter(f => f.status === "unknown").length;

  // Page d'accueil
  if (appState === "welcome") {
    return (
      <div className="min-h-screen bg-black text-white">
        <div className="fixed inset-0 bg-gradient-to-br from-violet-950/40 via-black to-purple-950/30 pointer-events-none" />
        
        <div className="relative min-h-screen flex flex-col items-center justify-center px-6">
          <div className="text-center max-w-2xl">
            <div className="mb-8">
              <span className="text-7xl">🛡️</span>
            </div>
            <h1 className="text-5xl font-bold mb-4 text-violet-400">Security Scanner</h1>
            <p className="text-xl text-gray-400 mb-2">
              Analysez la sécurité de votre système en quelques clics
            </p>
            <p className="text-sm text-gray-500 mb-12">
              Basé sur Microsoft Security Baselines & CIS Benchmarks
            </p>

            {error && (
              <div className="mb-6 p-4 bg-red-900/30 border border-red-500/30 rounded-xl text-red-400">
                ❌ {error}
              </div>
            )}

            <button
              onClick={startScan}
              className="px-8 py-4 text-lg bg-violet-600 hover:bg-violet-500 text-white font-bold rounded-xl transition-all hover:scale-105 shadow-lg shadow-violet-500/25"
            >
              🔍 Lancer l'analyse de sécurité
            </button>

            <p className="mt-8 text-xs text-gray-600">v{APP_VERSION}</p>
          </div>
        </div>
      </div>
    );
  }

  // Page de scan en cours
  if (appState === "scanning") {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="fixed inset-0 bg-gradient-to-br from-violet-950/40 via-black to-purple-950/30 pointer-events-none" />
        <div className="relative text-center">
          <div className="w-16 h-16 border-4 border-violet-500/30 border-t-violet-500 rounded-full animate-spin mb-4 mx-auto" />
          <h2 className="text-2xl font-bold mb-2 text-violet-400">Analyse en cours...</h2>
          <p className="text-gray-400">Vérification des paramètres de sécurité</p>
        </div>
      </div>
    );
  }

  // Page des résultats
  return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 bg-gradient-to-br from-violet-950/40 via-black to-purple-950/30 pointer-events-none" />
      
      {/* Header */}
      <header className="relative border-b border-violet-500/20 bg-black/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold text-violet-400">Security Scanner</span>
          </div>
          <button
            onClick={resetScan}
            className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white font-medium transition"
          >
            🔄 Nouvelle analyse
          </button>
        </div>
      </header>

      <main className="relative container mx-auto px-6 py-8">
        {/* System Info */}
        <div className="mb-6 p-4 rounded-xl bg-violet-900/20 border border-violet-500/30">
          <div className="grid md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Système : </span>
              <span className="text-white font-medium">{scanResult?.system.osName}</span>
            </div>
            <div>
              <span className="text-gray-400">Édition : </span>
              <span className="text-white font-medium">{scanResult?.system.osEdition || "N/A"}</span>
            </div>
            <div>
              <span className="text-gray-400">Machine : </span>
              <span className="text-white font-medium">{scanResult?.system.manufacturer} {scanResult?.system.model}</span>
            </div>
            <div>
              <span className="text-gray-400">Baseline : </span>
              <span className="text-violet-400 font-medium">{scanResult?.baseline}</span>
            </div>
          </div>
        </div>

        {/* Stats */}
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

        {/* Filters */}
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
              className={`px-4 py-2 rounded-lg font-medium transition ${
                filter === tab.key
                  ? "bg-violet-600 text-white"
                  : "bg-violet-900/30 text-gray-400 hover:bg-violet-900/50"
              }`}
            >
              {tab.label} ({tab.count})
            </button>
          ))}
        </div>

        {/* Findings List */}
        <div className="space-y-3">
          {filteredFindings.map((finding) => (
            <div
              key={finding.id}
              className={`rounded-xl border transition-all ${
                finding.status === "pass" 
                  ? "bg-green-900/10 border-green-500/30" 
                  : finding.status === "fail"
                  ? "bg-red-900/10 border-red-500/30"
                  : "bg-yellow-900/10 border-yellow-500/30"
              }`}
            >
              <button
                onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
                className="w-full p-4 flex items-center gap-4 text-left"
              >
                {/* Status Icon */}
                <span className={`text-xl ${
                  finding.status === "pass" ? "text-green-400" :
                  finding.status === "fail" ? "text-red-400" : "text-yellow-400"
                }`}>
                  {finding.status === "pass" ? "✓" : finding.status === "fail" ? "✗" : "?"}
                </span>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="text-xs font-mono text-gray-500">{finding.id}</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      finding.severity === "Critical" ? "bg-red-500/20 text-red-400" :
                      finding.severity === "High" ? "bg-orange-500/20 text-orange-400" :
                      finding.severity === "Medium" ? "bg-yellow-500/20 text-yellow-400" :
                      "bg-blue-500/20 text-blue-400"
                    }`}>
                      {finding.severity || "Medium"}
                    </span>
                  </div>
                  <p className="font-medium text-white truncate">{finding.name}</p>
                </div>

                {/* Arrow */}
                <span className={`text-gray-500 transition-transform ${expandedFinding === finding.id ? "rotate-180" : ""}`}>
                  ▼
                </span>
              </button>

              {/* Expanded Content */}
              {expandedFinding === finding.id && (
                <div className="px-4 pb-4 pt-0 border-t border-white/10 mt-2">
                  {/* Explication pour les non vérifiés */}
                  {finding.status === "unknown" && (
                    <div className="mt-4 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                      <p className="text-xs text-yellow-400 mb-2 font-semibold">
                        {getUnknownReason(finding).icon} Pourquoi cette analyse n'a pas pu être réalisée ?
                      </p>
                      <p className="text-sm text-gray-300 mb-2">
                        <strong>Raison :</strong> {getUnknownReason(finding).reason}
                      </p>
                      <p className="text-sm text-gray-300">
                        <strong>Solution :</strong> {getUnknownReason(finding).solution}
                      </p>
                    </div>
                  )}

                  {/* Description */}
                  {finding.description && (
                    <div className="mt-4 p-3 rounded-lg bg-blue-500/10 border border-blue-500/30">
                      <p className="text-xs text-blue-400 mb-2 font-semibold">💡 C'est quoi ?</p>
                      <p className="text-sm text-gray-300">{finding.description}</p>
                    </div>
                  )}

                  {/* Risque */}
                  {finding.status === "fail" && finding.risk && (
                    <div className="mt-4 p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
                      <p className="text-xs text-orange-400 mb-2 font-semibold">⚠️ Risque</p>
                      <p className="text-sm text-gray-300">{finding.risk}</p>
                    </div>
                  )}

                  {/* Valeurs */}
                  <div className="grid md:grid-cols-2 gap-4 mt-4">
                    <div className="p-3 rounded-lg bg-green-500/10">
                      <p className="text-xs text-green-400 mb-1">✓ Valeur recommandée</p>
                      <code className="text-sm text-white">{finding.recommendedValue ?? "N/A"}</code>
                    </div>
                    <div className={`p-3 rounded-lg ${finding.status === "pass" ? "bg-green-500/10" : "bg-red-500/10"}`}>
                      <p className={`text-xs mb-1 ${finding.status === "pass" ? "text-green-400" : "text-red-400"}`}>
                        {finding.status === "pass" ? "✓" : "✗"} Valeur actuelle
                      </p>
                      <code className="text-sm text-white">{finding.currentValue ?? "Non définie"}</code>
                    </div>
                  </div>

                  {/* Remédiation */}
                  {finding.remediation && finding.status === "fail" && (
                    <div className="mt-4 p-3 rounded-lg bg-violet-500/10 border border-violet-500/30">
                      <p className="text-xs text-violet-400 mb-3 font-semibold">🔧 Comment corriger ?</p>
                      {typeof finding.remediation === "string" ? (
                        <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono bg-black/30 p-2 rounded">
                          {finding.remediation}
                        </pre>
                      ) : (
                        <div className="space-y-3">
                          {finding.remediation.default && (
                            <div>
                              <p className="text-xs text-gray-500 mb-1">💻 Commande PowerShell :</p>
                              <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono bg-black/30 p-2 rounded">
                                {finding.remediation.default}
                              </pre>
                            </div>
                          )}
                          {finding.remediation.gpo && scanResult?.system.osEdition !== "Home" && (
                            <div>
                              <p className="text-xs text-gray-500 mb-1">🏢 Stratégie de groupe (GPO) :</p>
                              <p className="text-sm text-cyan-300 bg-black/30 p-2 rounded">
                                {finding.remediation.gpo}
                              </p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  <p className="mt-3 text-xs text-gray-500">
                    Méthode: {finding.method || "N/A"} • Catégorie: {finding.category || "N/A"}
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
