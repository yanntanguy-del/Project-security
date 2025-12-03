"use client";

import { useState, useEffect } from "react";

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
  // Account Policies
  "Account lockout duration": "Durée de verrouillage du compte",
  "Account lockout threshold": "Seuil de verrouillage du compte",
  "Allow Administrator account lockout": "Autoriser le verrouillage du compte Administrateur",
  "Length of password history maintained": "Historique des mots de passe conservés",
  "Minimum password length": "Longueur minimale du mot de passe",
  "Password must meet complexity requirements": "Complexité du mot de passe requise",
  "Store passwords using reversible encryption": "Stocker les mots de passe de façon réversible",
  
  // Security Options
  "Accounts: Limit local account use of blank passwords to console logon only": "Limiter les mots de passe vides aux connexions locales",
  "Interactive logon: Machine inactivity limit": "Verrouillage automatique après inactivité",
  "Microsoft network client: Digitally sign communications (always)": "Signature numérique des communications réseau",
  "Network security: Do not store LAN Manager hash value": "Ne pas stocker le hash LAN Manager",
  "Network security: LAN Manager authentication level": "Niveau d'authentification LAN Manager",
  "User Account Control: Admin Approval Mode for Built-in Administrator": "UAC : Mode d'approbation pour Administrateur intégré",
  "User Account Control: Behavior of elevation prompt for administrators": "UAC : Comportement de l'invite d'élévation",
  "User Account Control: Run all administrators in Admin Approval Mode": "UAC : Mode d'approbation pour tous les admins",
  "User Account Control: Behavior for administrators with Administrator protection": "UAC : Protection renforcée des administrateurs",
  "User Account Control: Configure type of Admin Approval Mode": "UAC : Type de mode d'approbation",
  
  // Windows Firewall
  "EnableFirewall (Domain Profile)": "Pare-feu activé (Profil Domaine)",
  "EnableFirewall (Private Profile)": "Pare-feu activé (Profil Privé)",
  "EnableFirewall (Public Profile)": "Pare-feu activé (Profil Public)",
  
  // MS Security Guide
  "Configure SMB v1 client driver": "Désactiver SMBv1 (client)",
  "Configure SMB v1 server": "Désactiver SMBv1 (serveur)",
  "WDigest Authentication": "Authentification WDigest désactivée",
  
  // Windows Defender
  "Turn on behavior monitoring": "Surveillance du comportement",
  "Turn on real-time protection": "Protection en temps réel",
  "Scan removable drives during a full scan": "Analyser les clés USB",
  "Turn on script scanning": "Analyser les scripts",
  "Turn on e-mail scanning": "Analyser les e-mails",
  "Configure detection for potentially unwanted applications": "Bloquer les applications indésirables",
  "Enable cloud-delivered protection": "Protection cloud Microsoft",
  "Enable network protection": "Protection réseau",
  "Prevent users and apps from accessing dangerous websites": "Bloquer les sites dangereux",
  
  // BitLocker
  "Require additional authentication at startup": "Authentification supplémentaire au démarrage",
  "Enable use of BitLocker authentication requiring preboot keyboard input": "Clavier au démarrage pour BitLocker",
  
  // Attack Surface Reduction
  "Block executable content from email client and webmail": "Bloquer les exécutables des e-mails",
  "Block Office applications from creating executable content": "Empêcher Office de créer des exécutables",
  "Block Office applications from injecting code into other processes": "Empêcher Office d'injecter du code",
  "Block JavaScript or VBScript from launching downloaded executable content": "Bloquer les scripts téléchargés",
  "Block execution of potentially obfuscated scripts": "Bloquer les scripts obfusqués",
  "Block Win32 API calls from Office macros": "Bloquer les appels API depuis les macros Office",
  "Block credential stealing from Windows local security authority subsystem": "Protection LSASS contre le vol de credentials",
  "Block process creations originating from PSExec and WMI commands": "Bloquer les processus via PSExec/WMI",
  "Block untrusted and unsigned processes that run from USB": "Bloquer les processus non signés USB",
  "Use advanced protection against ransomware": "Protection avancée anti-ransomware",
  "Block Adobe Reader from creating child processes": "Empêcher Adobe Reader de créer des processus",
  "Block Office communication application from creating child processes": "Empêcher Outlook de créer des processus",
  "Block persistence through WMI event subscription": "Bloquer la persistance WMI",
  "Block abuse of exploited vulnerable signed drivers": "Bloquer les pilotes vulnérables exploités",
  
  // Remote Desktop
  "Require secure RPC communication": "Communication RPC sécurisée requise",
  "Require use of specific security layer for remote (RDP) connections": "Couche de sécurité RDP",
  "Require user authentication for remote connections by using Network Level Authentication": "Authentification réseau (NLA) pour RDP",
  "Set client connection encryption level": "Niveau de chiffrement RDP",
  "Do not allow passwords to be saved": "Interdire la sauvegarde des mots de passe RDP",
  "Always prompt for password upon connection": "Toujours demander le mot de passe RDP",
  
  // Audit
  "Audit Credential Validation": "Auditer la validation des identifiants",
  "Audit Security Group Management": "Auditer la gestion des groupes",
  "Audit User Account Management": "Auditer la gestion des comptes",
  "Audit PNP Activity": "Auditer l'activité Plug & Play",
  "Audit Process Creation": "Auditer la création de processus",
  "Audit Account Lockout": "Auditer les verrouillages de compte",
  "Audit Logon": "Auditer les connexions",
  "Audit Special Logon": "Auditer les connexions spéciales",
  "Audit Audit Policy Change": "Auditer les changements de stratégie",
  "Audit Authentication Policy Change": "Auditer les changements d'authentification",
  "Audit Sensitive Privilege Use": "Auditer l'utilisation de privilèges sensibles",
  "Audit Security State Change": "Auditer les changements d'état de sécurité",
  "Audit Security System Extension": "Auditer les extensions système",
  "Audit System Integrity": "Auditer l'intégrité du système",
  
  // Services
  "Windows Remote Management (WS-Management)": "Gestion à distance Windows (WinRM)",
  "Xbox Services": "Services Xbox",
  "Bluetooth Support Service": "Service Bluetooth",
  "Downloaded Maps Manager": "Gestionnaire de cartes téléchargées",
  "Geolocation Service": "Service de géolocalisation",
  "Link-Layer Topology Discovery Mapper": "Détection de topologie réseau",
  "Microsoft iSCSI Initiator Service": "Service iSCSI",
  "Peer Networking Services": "Services réseau pair-à-pair",
  "Remote Registry": "Registre distant",
  "Routing and Remote Access": "Routage et accès distant",
  "Simple TCP/IP Services": "Services TCP/IP simples",
  "SNMP Service": "Service SNMP",
  "Windows Error Reporting Service": "Service de rapport d'erreurs",
  "Windows Media Player Network Sharing Service": "Partage réseau Windows Media",
  "Windows Mobile Hotspot Service": "Point d'accès mobile Windows",
  "Remote Desktop Services": "Services Bureau à distance",
  
  // Privacy
  "Let apps access your location": "Autoriser l'accès à la localisation",
  "Let apps access your camera": "Autoriser l'accès à la caméra",
  "Let apps access your microphone": "Autoriser l'accès au micro",
  "Let apps access your notifications": "Autoriser l'accès aux notifications",
  "Let apps access your account info": "Autoriser l'accès aux infos du compte",
  "Let apps access your contacts": "Autoriser l'accès aux contacts",
  "Let apps access your calendar": "Autoriser l'accès au calendrier",
  "Let apps read or send messages": "Autoriser l'accès aux messages",
  "Let apps control radios": "Autoriser le contrôle des radios",
  "Let apps access your call history": "Autoriser l'accès à l'historique d'appels",
  "Let apps make phone calls": "Autoriser les appels téléphoniques",
  "Let apps access trusted devices": "Autoriser l'accès aux appareils de confiance",
  "Let apps access your email": "Autoriser l'accès aux e-mails",
  "Let apps access Tasks": "Autoriser l'accès aux tâches",
  "Let apps access diagnostic info about other apps": "Autoriser l'accès au diagnostic d'apps",
  
  // OEM
  "Dell SupportAssist Service": "Service Dell SupportAssist",
  "Dell Data Vault Collector": "Collecteur de données Dell",
  "HP Support Assistant": "Service HP Support Assistant",
  "HP Telemetry": "Télémétrie HP",
  "HP Sure Click": "HP Sure Click",
  "Lenovo Vantage Service": "Service Lenovo Vantage",
  "Lenovo System Update": "Lenovo System Update",
  "Lenovo Customer Feedback Program": "Programme de feedback Lenovo",
  "ASUS System Control Interface": "Interface de contrôle ASUS",
  "ASUS Link Near": "ASUS Link Near",
  "Acer Quick Access Service": "Service Acer Quick Access",
  "Acer Collection": "Collecte de données Acer",
};

// Traduire le nom d'un finding
const translateName = (name: string): string => {
  return translations[name] || name;
};

// Traduire la catégorie
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
    "Enterprise Features": "Fonctionnalités Enterprise",
    "OEM - Dell": "Fabricant - Dell",
    "OEM - HP": "Fabricant - HP",
    "OEM - Lenovo": "Fabricant - Lenovo",
    "OEM - ASUS": "Fabricant - ASUS",
    "OEM - Acer": "Fabricant - Acer",
  };
  return categoryTranslations[category] || category;
};

// Traduire la sévérité
const translateSeverity = (severity: string): string => {
  const severityTranslations: Record<string, string> = {
    "Critical": "Critique",
    "High": "Élevé",
    "Medium": "Moyen",
    "Low": "Faible",
  };
  return severityTranslations[severity] || severity;
};

export default function HomePage() {
  const [loading, setLoading] = useState(true);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "pass" | "fail" | "unknown">("all");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  // Lancer le scan automatiquement au démarrage
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
  const visibleFindings = scanResult?.findings || [];

  const filteredFindings = visibleFindings.filter((f) => 
    filter === "all" || f.status === filter
  );

  const passCount = visibleFindings.filter(f => f.status === "pass").length;
  const failCount = visibleFindings.filter(f => f.status === "fail").length;
  const unknownCount = visibleFindings.filter(f => f.status === "unknown").length;

  // Fonction pour expliquer pourquoi une analyse n'a pas pu être faite
  const getUnknownReason = (finding: Finding): { reason: string; solution: string; icon: string } => {
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
    if (finding.currentValue?.includes("Non disponible sur Windows Home")) {
      return {
        reason: "Cette fonctionnalité n'est pas disponible sur Windows Home",
        solution: "Cette protection nécessite Windows Pro ou Enterprise. Envisagez une mise à niveau si vous avez besoin de cette sécurité.",
        icon: "🏠"
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
        {/* Loading */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20">
            <div className="w-16 h-16 border-4 border-violet-500/30 border-t-violet-500 rounded-full animate-spin mb-4" />
            <p className="text-gray-400">Analyse de sécurité en cours...</p>
            <p className="text-sm text-gray-500 mt-2">Détection du système et vérification des paramètres</p>
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
            {/* System Info */}
            <div className="mb-6 p-4 rounded-xl bg-violet-900/20 border border-violet-500/30">
              <div className="grid md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-gray-400">Système : </span>
                  <span className="text-white font-medium">{scanResult.system.osName}</span>
                </div>
                <div>
                  <span className="text-gray-400">Édition : </span>
                  <span className="text-white font-medium">{scanResult.system.osEdition || "N/A"}</span>
                </div>
                <div>
                  <span className="text-gray-400">Machine : </span>
                  <span className="text-white font-medium">{scanResult.system.manufacturer} {scanResult.system.model}</span>
                </div>
                <div>
                  <span className="text-gray-400">Baseline : </span>
                  <span className="text-violet-400 font-medium">{scanResult.baseline}</span>
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
                        <span className="text-xs font-mono text-gray-500">{String(finding.id)}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          finding.severity === "Critical" ? "bg-red-500/20 text-red-400" :
                          finding.severity === "High" ? "bg-orange-500/20 text-orange-400" :
                          finding.severity === "Medium" ? "bg-yellow-500/20 text-yellow-400" :
                          "bg-blue-500/20 text-blue-400"
                        }`}>
                          {translateSeverity(String(finding.severity || "Medium"))}
                        </span>
                        <span className="text-xs text-gray-600">
                          {translateCategory(finding.category)}
                        </span>
                      </div>
                      <p className="font-medium text-white truncate">{translateName(String(finding.name || "Sans nom"))}</p>
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
                        <div className={`p-3 rounded-lg ${finding.status === "pass" ? "bg-green-500/10" : finding.status === "unknown" ? "bg-yellow-500/10" : "bg-red-500/10"}`}>
                          <p className={`text-xs mb-1 ${finding.status === "pass" ? "text-green-400" : finding.status === "unknown" ? "text-yellow-400" : "text-red-400"}`}>
                            {finding.status === "pass" ? "✓" : finding.status === "unknown" ? "?" : "✗"} Valeur actuelle
                          </p>
                          <code className="text-sm text-white">
                            {finding.currentValue?.includes("(non configuré)") 
                              ? "Non configuré (Windows utilise la valeur par défaut)"
                              : finding.currentValue ?? "Non définie"}
                          </code>
                          {finding.currentValue?.includes("(non configuré)") && finding.defaultValue && (
                            <p className="text-xs text-gray-500 mt-1">
                              Valeur par défaut Windows : {finding.defaultValue}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* Note explicative pour les valeurs non configurées */}
                      {finding.currentValue?.includes("(non configuré)") && finding.status === "fail" && (
                        <div className="mt-3 p-2 rounded-lg bg-blue-500/5 border border-blue-500/20">
                          <p className="text-xs text-blue-400">
                            ℹ️ <strong>Scan effectué</strong> - Ce paramètre n'est pas explicitement configuré dans le registre Windows. 
                            Le système utilise donc la valeur par défaut, qui ne correspond pas à la recommandation de sécurité.
                          </p>
                        </div>
                      )}

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
                        Méthode: {finding.method || "N/A"} • Catégorie: {translateCategory(finding.category) || "N/A"}
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
