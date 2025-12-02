"use client";

import { useState, useEffect } from "react";
import Link from "next/link";

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

export default function FindingsPage() {
  const [loading, setLoading] = useState(true);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "pass" | "fail" | "unknown">("all");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  useEffect(() => {
    runScan();
  }, []);

  const runScan = async () => {
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

  // Les findings incompatibles sont déjà filtrés par l'API
  // On affiche tous les findings retournés
  const visibleFindings = scanResult?.findings || [];

  const filteredFindings = visibleFindings.filter((f) => 
    filter === "all" || f.status === filter
  );

  const passCount = visibleFindings.filter(f => f.status === "pass").length;
  const failCount = visibleFindings.filter(f => f.status === "fail").length;
  const unknownCount = visibleFindings.filter(f => f.status === "unknown").length;

  // Fonction pour expliquer pourquoi une analyse n'a pas pu être faite
  const getUnknownReason = (finding: Finding): { reason: string; solution: string; icon: string } => {
    // Utiliser le skipReason s'il est défini
    if (finding.skipReason) {
      switch (finding.skipReason) {
        case "edition_incompatible":
          return {
            reason: "Cette fonctionnalité n'est pas disponible sur votre version de Windows (Home)",
            solution: "Cette protection n'est disponible que sur Windows Pro ou Enterprise. Si vous avez besoin de cette sécurité, envisagez de mettre à niveau votre édition Windows.",
            icon: "🏠"
          };
        case "cpu_no_cet":
          return {
            reason: "Votre processeur ne supporte pas la protection CET (Control-flow Enforcement Technology)",
            solution: "Cette protection matérielle nécessite un processeur Intel de 11e génération ou plus récent, ou AMD Zen 3 ou plus récent. Aucune action n'est possible avec votre matériel actuel.",
            icon: "🔧"
          };
        case "cpu_no_vbs":
          return {
            reason: "La virtualisation matérielle (VBS) n'est pas supportée ou est désactivée",
            solution: "Vérifiez dans le BIOS/UEFI que la virtualisation (Intel VT-x ou AMD-V) est activée. Si votre processeur ne supporte pas la virtualisation, cette protection ne peut pas être activée.",
            icon: "🔧"
          };
        case "admin_required":
          return {
            reason: "Ce paramètre de sécurité Windows nécessite des droits administrateur pour être lu",
            solution: "Fermez l'application, puis faites clic-droit sur l'icône → 'Exécuter en tant qu'administrateur' pour analyser ce paramètre.",
            icon: "🔐"
          };
        case "registry_not_configured":
          return {
            reason: "Ce paramètre n'est pas configuré dans le registre Windows",
            solution: "Windows utilise probablement la valeur par défaut. Vous pouvez appliquer la remédiation suggérée pour configurer explicitement ce paramètre.",
            icon: "📝"
          };
        case "account_policy_error":
          return {
            reason: "Impossible de lire les stratégies de compte Windows",
            solution: "Essayez d'exécuter l'application en tant qu'administrateur, ou vérifiez que le service de stratégie locale fonctionne correctement.",
            icon: "⚙️"
          };
        case "service_not_installed":
          return {
            reason: "Le service Windows vérifié n'est pas installé sur votre système",
            solution: "Ce service peut ne pas être disponible sur votre édition de Windows, ou il a été supprimé/désactivé. Vérifiez si c'est intentionnel.",
            icon: "🔌"
          };
        case "manual_check":
          return {
            reason: "Cette vérification doit être faite manuellement",
            solution: "Ce paramètre ne peut pas être détecté automatiquement. Vous devez vérifier vous-même (ex: vérifier le BIOS, un paramètre physique, ou une configuration externe).",
            icon: "👤"
          };
      }
    }
    
    // Fallback basé sur le method ou currentValue si pas de skipReason
    if (finding.method === "manual") {
      return {
        reason: "Cette vérification nécessite une action manuelle",
        solution: "Vous devez vérifier ce paramètre vous-même (ex: accéder au BIOS, vérifier une configuration physique)",
        icon: "👤"
      };
    }
    if (finding.method === "secedit") {
      return {
        reason: "Ce paramètre fait partie des stratégies de sécurité Windows qui nécessitent des droits élevés",
        solution: "Fermez l'application, puis faites clic-droit → 'Exécuter en tant qu'administrateur' pour analyser ce paramètre",
        icon: "🔐"
      };
    }
    if (finding.currentValue?.includes("Droits admin")) {
      return {
        reason: "Ce paramètre système ne peut être lu qu'avec des privilèges administrateur",
        solution: "Fermez l'application, puis faites clic-droit → 'Exécuter en tant qu'administrateur' pour analyser ce paramètre",
        icon: "🔐"
      };
    }
    if (finding.currentValue?.includes("Non configuré") || finding.currentValue?.includes("(non configuré)")) {
      return {
        reason: "Ce paramètre n'est pas explicitement configuré sur votre système",
        solution: "Windows utilise sa valeur par défaut. Vous pouvez appliquer la remédiation pour le configurer selon les recommandations de sécurité.",
        icon: "⚠️"
      };
    }
    if (finding.currentValue?.includes("(valeur Windows)")) {
      return {
        reason: "La valeur affichée est celle par défaut de Windows",
        solution: "Vous pouvez appliquer la remédiation pour modifier ce paramètre selon les recommandations de sécurité.",
        icon: "ℹ️"
      };
    }
    if (finding.currentValue?.includes("Non disponible sur Windows Home")) {
      return {
        reason: "Cette fonctionnalité n'est pas disponible sur Windows Home",
        solution: "Cette protection nécessite Windows Pro ou Enterprise. Envisagez une mise à niveau si vous avez besoin de cette sécurité.",
        icon: "🏠"
      };
    }
    if (finding.currentValue?.includes("Processeur non compatible")) {
      return {
        reason: "Votre processeur ne supporte pas cette fonctionnalité de sécurité",
        solution: "Cette protection matérielle nécessite un processeur plus récent. Aucune action logicielle n'est possible.",
        icon: "🔧"
      };
    }
    return {
      reason: "La valeur de ce paramètre n'a pas pu être déterminée",
      solution: "Essayez de relancer le scan ou vérifiez manuellement ce paramètre dans les paramètres Windows",
      icon: "❓"
    };
  };

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-violet-950/40 via-black to-purple-950/30 pointer-events-none" />
      
      {/* Header */}
      <header className="relative border-b border-violet-500/20 bg-black/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold text-violet-400">HardeningKitty</span>
          </Link>
          <button
            onClick={runScan}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white font-medium transition disabled:opacity-50"
          >
            {loading ? "⏳ Analyse..." : "🔄 Relancer"}
          </button>
        </div>
      </header>

      <main className="relative container mx-auto px-6 py-8">
        {/* Loading */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20">
            <div className="w-16 h-16 border-4 border-violet-500/30 border-t-violet-500 rounded-full animate-spin mb-4" />
            <p className="text-gray-400">Analyse en cours...</p>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div className="text-center py-20">
            <p className="text-red-400 mb-4">❌ {error}</p>
            <button onClick={runScan} className="px-6 py-2 rounded-lg bg-violet-600 hover:bg-violet-500">
              Réessayer
            </button>
          </div>
        )}

        {/* Results */}
        {scanResult && !loading && (
          <>
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
                        <span className="text-xs font-mono text-gray-500">{String(finding.id)}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          finding.severity === "Critical" ? "bg-red-500/20 text-red-400" :
                          finding.severity === "High" ? "bg-orange-500/20 text-orange-400" :
                          finding.severity === "Medium" ? "bg-yellow-500/20 text-yellow-400" :
                          "bg-blue-500/20 text-blue-400"
                        }`}>
                          {String(finding.severity || "Medium")}
                        </span>
                      </div>
                      <p className="font-medium text-white truncate">{String(finding.name || "Sans nom")}</p>
                    </div>

                    {/* Arrow */}
                    <span className={`text-gray-500 transition-transform ${expandedFinding === finding.id ? "rotate-180" : ""}`}>
                      ▼
                    </span>
                  </button>

                  {/* Expanded Content */}
                  {expandedFinding === finding.id && (
                    <div className="px-4 pb-4 pt-0 border-t border-white/10 mt-2">
                      {/* Explication pour les analyses non réalisées */}
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
                          {finding.method === "manual" && finding.remediation && typeof finding.remediation === "object" && finding.remediation.manual && (
                            <div className="mt-3 p-2 rounded bg-yellow-500/5 border border-yellow-500/20">
                              <p className="text-xs text-yellow-300 mb-1">📋 Instructions de vérification manuelle :</p>
                              <p className="text-sm text-gray-300">{finding.remediation.manual}</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Description - C'est quoi ce paramètre ? */}
                      {finding.description && (
                        <div className="mt-4 p-3 rounded-lg bg-blue-500/10 border border-blue-500/30">
                          <p className="text-xs text-blue-400 mb-2 font-semibold">💡 C'est quoi ?</p>
                          <p className="text-sm text-gray-300">{String(finding.description)}</p>
                        </div>
                      )}

                      {/* Compatibilité - Prérequis système */}
                      {finding.compatibility && finding.status === "unknown" && (
                        <div className="mt-4 p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
                          <p className="text-xs text-cyan-400 mb-2 font-semibold">💻 Compatibilité système</p>
                          <p className="text-sm text-gray-300">{String(finding.compatibility)}</p>
                        </div>
                      )}

                      {/* Risque - Pourquoi c'est important (pour fail ET unknown non configuré) */}
                      {(finding.status === "fail" || (finding.status === "unknown" && finding.currentValue?.includes("Non configuré"))) && (
                        <div className="mt-4 p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
                          <p className="text-xs text-orange-400 mb-2 font-semibold">
                            {finding.status === "unknown" ? "⚠️ Pourquoi activer cette protection ?" : "⚠️ Pourquoi c'est un problème ?"}
                          </p>
                          <p className="text-sm text-gray-300">
                            {finding.risk || (
                              finding.severity === "Critical" ? "Ce paramètre critique expose votre système à des attaques graves. Un pirate pourrait prendre le contrôle total de votre ordinateur." :
                              finding.severity === "High" ? "Ce paramètre affaiblit sérieusement la protection de votre système. Les pirates connaissent cette faille et peuvent l'exploiter facilement." :
                              finding.severity === "Medium" ? "Ce paramètre représente une porte d'entrée potentielle pour les pirates. Il est recommandé de le corriger." :
                              "Ce paramètre améliorerait la sécurité générale de votre système."
                            )}
                          </p>
                        </div>
                      )}

                      {/* Valeurs - seulement si pas manuel */}
                      {finding.method !== "manual" && (
                        <div className="grid md:grid-cols-2 gap-4 mt-4">
                          <div className="p-3 rounded-lg bg-green-500/10">
                            <p className="text-xs text-green-400 mb-1">✓ Valeur recommandée</p>
                            <code className="text-sm text-white">{String(finding.recommendedValue ?? "N/A")}</code>
                          </div>
                          <div className={`p-3 rounded-lg ${finding.status === "pass" ? "bg-green-500/10" : "bg-red-500/10"}`}>
                            <p className={`text-xs mb-1 ${finding.status === "pass" ? "text-green-400" : "text-red-400"}`}>
                              {finding.status === "pass" ? "✓" : "✗"} Valeur actuelle
                            </p>
                            <code className="text-sm text-white">{String(finding.currentValue ?? "Non définie")}</code>
                          </div>
                        </div>
                      )}

                      {/* Remédiation - pour fail ET unknown non configuré */}
                      {finding.remediation && (finding.status === "fail" || (finding.status === "unknown" && finding.currentValue?.includes("Non configuré"))) && (
                        <div className="mt-4 p-3 rounded-lg bg-violet-500/10 border border-violet-500/30">
                          <p className="text-xs text-violet-400 mb-3 font-semibold">🔧 Comment activer cette protection ?</p>
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
                              {/* GPO uniquement pour Pro/Enterprise */}
                              {finding.remediation.gpo && scanResult?.system.osEdition !== "Home" && (
                                <div>
                                  <p className="text-xs text-gray-500 mb-1">🏢 Stratégie de groupe (GPO) :</p>
                                  <p className="text-sm text-cyan-300 bg-black/30 p-2 rounded">
                                    {finding.remediation.gpo}
                                  </p>
                                </div>
                              )}
                              {/* Intune uniquement pour Pro/Enterprise */}
                              {finding.remediation.intune && scanResult?.system.osEdition !== "Home" && (
                                <div>
                                  <p className="text-xs text-gray-500 mb-1">☁️ Microsoft Intune :</p>
                                  <p className="text-sm text-purple-300 bg-black/30 p-2 rounded">
                                    {finding.remediation.intune}
                                  </p>
                                </div>
                              )}
                              {finding.remediation.manual && (
                                <div>
                                  <p className="text-xs text-gray-500 mb-1">📝 Instructions manuelles :</p>
                                  <p className="text-sm text-yellow-300 bg-black/30 p-2 rounded">
                                    {finding.remediation.manual}
                                  </p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      <p className="mt-3 text-xs text-gray-500">
                        Méthode: {String(finding.method || "N/A")} • Catégorie: {String(finding.category || "N/A")}
                      </p>
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
