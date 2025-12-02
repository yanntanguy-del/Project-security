/**
 * lib/findings.ts
 * Système adaptatif de détection et remédiation de sécurité
 * 
 * Fonctionnalités:
 * - Détection automatique du système (OS, version, édition, fabricant)
 * - Sélection dynamique des findings selon le système détecté
 * - Remédiation adaptée à l'édition (Home/Pro/Enterprise) et au fabricant
 * - Chargement des baselines depuis des fichiers JSON
 */

// ============================================
// TYPES
// ============================================

export type OSFamily = 'Windows' | 'Linux' | 'macOS' | 'Unknown';

export type DetectedSystem = {
  osFamily: OSFamily;
  osName?: string;
  osVersion?: string;
  osEdition?: string;
  buildNumber?: string;
  manufacturer?: string;
  model?: string;
  detectedAt?: string;
};

export type Severity = 'Low' | 'Medium' | 'High' | 'Critical';

export type RemediationMethod = 'GUI' | 'CLI' | 'PowerShell' | 'Registry' | 'GPO' | 'Note';

export type RemediationVariant = {
  edition?: string;           // Home, Pro, Enterprise, Education
  manufacturer?: string;      // Dell, HP, Lenovo, etc.
  osFamily?: OSFamily;
  minBuild?: string;
  maxBuild?: string;
  method: RemediationMethod;
  instruction: string;
  command?: string;           // Commande à exécuter si CLI/PowerShell
};

export type FindingEntry = {
  id: string;
  title: string;
  name?: string;
  category?: string;
  severity: Severity;
  description?: string;
  
  // Remédiation générique (fallback)
  remediation?: string;
  recommended?: string;
  
  // Remédiations spécifiques par édition/fabricant
  remediationVariants?: RemediationVariant[];
  
  // Règles d'applicabilité
  appliesTo?: {
    osFamily?: OSFamily[];
    editions?: string[];
    manufacturers?: string[];
    models?: string[];
    minBuild?: string;
    maxBuild?: string;
  };
};

// ============================================
// BIBLIOTHÈQUE DE FINDINGS
// ============================================

export const FindingsLibrary: FindingEntry[] = [
  // Windows Firewall
  {
    id: 'FW-001',
    title: 'Windows Firewall',
    category: 'Network Security',
    severity: 'High',
    description: 'Le pare-feu Windows doit être activé pour tous les profils (Domaine, Privé, Public).',
    remediation: 'Activer le pare-feu Windows via le Panneau de configuration.',
    remediationVariants: [
      {
        edition: 'Home',
        method: 'GUI',
        instruction: 'Paramètres > Confidentialité et sécurité > Sécurité Windows > Pare-feu et protection réseau > Activer pour tous les réseaux'
      },
      {
        edition: 'Pro',
        method: 'PowerShell',
        instruction: 'Exécuter la commande PowerShell suivante en tant qu\'administrateur',
        command: 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'
      },
      {
        edition: 'Enterprise',
        method: 'GPO',
        instruction: 'Utiliser la stratégie de groupe: Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Pare-feu Windows avec sécurité avancée'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // SMBv1
  {
    id: 'SMB-001',
    title: 'Protocole SMBv1',
    category: 'Network Security',
    severity: 'High',
    description: 'Le protocole SMBv1 est obsolète et vulnérable (WannaCry, EternalBlue). Il doit être désactivé.',
    remediation: 'Désactiver SMBv1 via les fonctionnalités Windows.',
    remediationVariants: [
      {
        edition: 'Home',
        method: 'GUI',
        instruction: 'Panneau de configuration > Programmes > Activer ou désactiver des fonctionnalités Windows > Décocher "Support de partage de fichiers SMB 1.0/CIFS"'
      },
      {
        edition: 'Pro',
        method: 'PowerShell',
        instruction: 'Exécuter en tant qu\'administrateur',
        command: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
      },
      {
        edition: 'Enterprise',
        method: 'GPO',
        instruction: 'Utiliser DISM ou GPO pour désactiver SMB1Protocol sur l\'ensemble du parc'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // Windows Update
  {
    id: 'UPD-001',
    title: 'Windows Update',
    category: 'System Updates',
    severity: 'High',
    description: 'Toutes les mises à jour de sécurité doivent être installées.',
    remediation: 'Vérifier et installer les mises à jour Windows.',
    remediationVariants: [
      {
        edition: 'Home',
        method: 'GUI',
        instruction: 'Paramètres > Windows Update > Rechercher des mises à jour > Installer toutes les mises à jour disponibles'
      },
      {
        edition: 'Pro',
        method: 'PowerShell',
        instruction: 'Utiliser le module PSWindowsUpdate',
        command: 'Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install -AcceptAll'
      },
      {
        edition: 'Enterprise',
        method: 'GPO',
        instruction: 'Configurer WSUS/SCCM pour la gestion centralisée des mises à jour'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // BitLocker / Device Encryption
  {
    id: 'ENC-001',
    title: 'Chiffrement du disque',
    category: 'Data Protection',
    severity: 'High',
    description: 'Le disque système doit être chiffré pour protéger les données en cas de vol.',
    remediation: 'Activer le chiffrement du disque.',
    remediationVariants: [
      {
        edition: 'Home',
        method: 'GUI',
        instruction: 'Windows Home ne supporte pas BitLocker. Utilisez le chiffrement de l\'appareil: Paramètres > Confidentialité et sécurité > Chiffrement de l\'appareil (si disponible avec TPM)'
      },
      {
        edition: 'Pro',
        method: 'PowerShell',
        instruction: 'Activer BitLocker sur le lecteur C:',
        command: 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector'
      },
      {
        edition: 'Enterprise',
        method: 'GPO',
        instruction: 'Configurer BitLocker via GPO: Configuration ordinateur > Modèles d\'administration > Composants Windows > Chiffrement de lecteur BitLocker'
      }
    ],
    appliesTo: { osFamily: ['Windows'], editions: ['Pro', 'Enterprise', 'Education', 'Home'] }
  },
  
  // Remote Desktop
  {
    id: 'RDP-001',
    title: 'Bureau à distance',
    category: 'Remote Access',
    severity: 'High',
    description: 'Le Bureau à distance doit être désactivé s\'il n\'est pas nécessaire.',
    remediation: 'Désactiver le Bureau à distance.',
    remediationVariants: [
      {
        edition: 'Home',
        method: 'Note',
        instruction: 'Windows Home ne supporte pas le serveur Bureau à distance. Vérifiez que l\'Assistance à distance est désactivée dans Système > Bureau à distance'
      },
      {
        edition: 'Pro',
        method: 'GUI',
        instruction: 'Paramètres > Système > Bureau à distance > Désactiver "Activer le Bureau à distance"'
      },
      {
        edition: 'Enterprise',
        method: 'GPO',
        instruction: 'Configuration ordinateur > Modèles d\'administration > Composants Windows > Services Bureau à distance > Hôte de session Bureau à distance > Connexions > Autoriser les utilisateurs à se connecter à distance = Désactivé'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // TPM
  {
    id: 'TPM-001',
    title: 'Module TPM',
    category: 'Hardware Security',
    severity: 'Medium',
    description: 'Le TPM (Trusted Platform Module) doit être présent et activé pour le chiffrement sécurisé.',
    remediation: 'Vérifier la présence et l\'activation du TPM.',
    remediationVariants: [
      {
        method: 'PowerShell',
        instruction: 'Vérifier l\'état du TPM',
        command: 'Get-Tpm'
      },
      {
        manufacturer: 'Dell',
        method: 'Note',
        instruction: 'Accéder au BIOS Dell (F2 au démarrage) > Security > TPM 2.0 Security > Activer'
      },
      {
        manufacturer: 'HP',
        method: 'Note',
        instruction: 'Accéder au BIOS HP (F10 au démarrage) > Security > TPM Embedded Security > Activer'
      },
      {
        manufacturer: 'Lenovo',
        method: 'Note',
        instruction: 'Accéder au BIOS Lenovo (F1 au démarrage) > Security > Security Chip > Activer'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // Secure Boot
  {
    id: 'BOOT-001',
    title: 'Secure Boot',
    category: 'Hardware Security',
    severity: 'High',
    description: 'Le Secure Boot doit être activé pour empêcher le chargement de logiciels malveillants au démarrage.',
    remediation: 'Activer le Secure Boot dans le BIOS/UEFI.',
    remediationVariants: [
      {
        method: 'PowerShell',
        instruction: 'Vérifier l\'état du Secure Boot',
        command: 'Confirm-SecureBootUEFI'
      },
      {
        manufacturer: 'Dell',
        method: 'Note',
        instruction: 'BIOS Dell (F2) > Secure Boot > Secure Boot Enable = Enabled'
      },
      {
        manufacturer: 'HP',
        method: 'Note',
        instruction: 'BIOS HP (F10) > Security > Secure Boot Configuration > Secure Boot = Enabled'
      },
      {
        manufacturer: 'Lenovo',
        method: 'Note',
        instruction: 'BIOS Lenovo (F1) > Security > Secure Boot > Secure Boot = Enabled'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // UAC
  {
    id: 'UAC-001',
    title: 'Contrôle de compte utilisateur (UAC)',
    category: 'Access Control',
    severity: 'Medium',
    description: 'L\'UAC doit être configuré au niveau maximum pour prévenir les élévations de privilèges non autorisées.',
    remediation: 'Configurer l\'UAC au niveau maximum.',
    remediationVariants: [
      {
        edition: 'Home',
        method: 'GUI',
        instruction: 'Panneau de configuration > Comptes d\'utilisateurs > Modifier les paramètres de contrôle de compte d\'utilisateur > Placer le curseur tout en haut'
      },
      {
        edition: 'Pro',
        method: 'Registry',
        instruction: 'Modifier le registre',
        command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2'
      }
    ],
    appliesTo: { osFamily: ['Windows'] }
  },
  
  // Linux SSH
  {
    id: 'SSH-001',
    title: 'Configuration SSH',
    category: 'Remote Access',
    severity: 'High',
    description: 'SSH doit être configuré de manière sécurisée (pas de root login, clés uniquement).',
    remediation: 'Configurer /etc/ssh/sshd_config correctement.',
    remediationVariants: [
      {
        osFamily: 'Linux',
        method: 'CLI',
        instruction: 'Éditer /etc/ssh/sshd_config et définir: PermitRootLogin no, PasswordAuthentication no, PubkeyAuthentication yes',
        command: 'sudo nano /etc/ssh/sshd_config && sudo systemctl restart sshd'
      }
    ],
    appliesTo: { osFamily: ['Linux'] }
  },
  
  // Linux Firewall
  {
    id: 'UFW-001',
    title: 'Pare-feu Linux (UFW/iptables)',
    category: 'Network Security',
    severity: 'High',
    description: 'Un pare-feu doit être actif sur les systèmes Linux.',
    remediation: 'Activer et configurer UFW.',
    remediationVariants: [
      {
        osFamily: 'Linux',
        method: 'CLI',
        instruction: 'Activer UFW et configurer les règles de base',
        command: 'sudo ufw enable && sudo ufw default deny incoming && sudo ufw default allow outgoing'
      }
    ],
    appliesTo: { osFamily: ['Linux'] }
  },
  
  // macOS FileVault
  {
    id: 'FV-001',
    title: 'FileVault (Chiffrement macOS)',
    category: 'Data Protection',
    severity: 'High',
    description: 'FileVault doit être activé pour chiffrer le disque sur macOS.',
    remediation: 'Activer FileVault.',
    remediationVariants: [
      {
        osFamily: 'macOS',
        method: 'GUI',
        instruction: 'Préférences Système > Sécurité et confidentialité > FileVault > Activer FileVault'
      },
      {
        osFamily: 'macOS',
        method: 'CLI',
        instruction: 'Activer FileVault via Terminal',
        command: 'sudo fdesetup enable'
      }
    ],
    appliesTo: { osFamily: ['macOS'] }
  },
  
  // macOS Gatekeeper
  {
    id: 'GK-001',
    title: 'Gatekeeper (macOS)',
    category: 'Application Security',
    severity: 'Medium',
    description: 'Gatekeeper doit être activé pour n\'autoriser que les applications signées.',
    remediation: 'Configurer Gatekeeper.',
    remediationVariants: [
      {
        osFamily: 'macOS',
        method: 'GUI',
        instruction: 'Préférences Système > Sécurité et confidentialité > Général > Autoriser les applications téléchargées de: App Store et développeurs identifiés'
      },
      {
        osFamily: 'macOS',
        method: 'CLI',
        instruction: 'Activer Gatekeeper via Terminal',
        command: 'sudo spctl --master-enable'
      }
    ],
    appliesTo: { osFamily: ['macOS'] }
  }
];

// ============================================
// FONCTIONS DE DÉTECTION
// ============================================

/**
 * Détecte le système actuel (côté serveur Node.js uniquement)
 */
export function detectSystem(): DetectedSystem {
  // Guard pour le navigateur
  if (typeof window !== 'undefined') {
    return {
      osFamily: 'Unknown',
      osName: 'Browser',
      detectedAt: new Date().toISOString()
    };
  }
  
  try {
    const os = require('os');
    const platform = os.platform();
    const release = os.release();
    
    let osFamily: OSFamily = 'Unknown';
    if (platform === 'win32') osFamily = 'Windows';
    else if (platform === 'darwin') osFamily = 'macOS';
    else if (platform === 'linux') osFamily = 'Linux';
    
    return {
      osFamily,
      osName: os.type(),
      osVersion: release,
      buildNumber: release.split('.').pop() || '',
      detectedAt: new Date().toISOString()
    };
  } catch (e) {
    return {
      osFamily: 'Unknown',
      detectedAt: new Date().toISOString()
    };
  }
}

/**
 * Détection Windows avancée via PowerShell (à appeler depuis Electron)
 */
export function getWindowsDetectionCommands(): string[] {
  return [
    // OS Info
    'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json -Compress',
    // Edition
    '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").EditionID',
    // Hardware
    'Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model | ConvertTo-Json -Compress'
  ];
}

/**
 * Parse la sortie de détection Windows
 */
export function parseWindowsDetection(osJson: string, edition: string, hwJson: string): DetectedSystem {
  try {
    const osInfo = JSON.parse(osJson);
    const hwInfo = JSON.parse(hwJson);
    
    // Déterminer la version Windows
    const caption = osInfo.Caption || '';
    let osVersion = '';
    if (caption.includes('11')) osVersion = '11';
    else if (caption.includes('10')) osVersion = '10';
    
    // Déterminer l'édition normalisée
    let normalizedEdition = edition?.trim() || '';
    if (normalizedEdition.toLowerCase().includes('home') || normalizedEdition === 'Core') {
      normalizedEdition = 'Home';
    } else if (normalizedEdition.toLowerCase().includes('pro')) {
      normalizedEdition = 'Pro';
    } else if (normalizedEdition.toLowerCase().includes('enterprise')) {
      normalizedEdition = 'Enterprise';
    } else if (normalizedEdition.toLowerCase().includes('education')) {
      normalizedEdition = 'Education';
    }
    
    return {
      osFamily: 'Windows',
      osName: caption,
      osVersion,
      osEdition: normalizedEdition,
      buildNumber: String(osInfo.BuildNumber || ''),
      manufacturer: hwInfo.Manufacturer || '',
      model: hwInfo.Model || '',
      detectedAt: new Date().toISOString()
    };
  } catch (e) {
    return {
      osFamily: 'Windows',
      osName: 'Windows (detection error)',
      detectedAt: new Date().toISOString()
    };
  }
}

// ============================================
// FONCTIONS DE SÉLECTION ET REMÉDIATION
// ============================================

/**
 * Sélectionne les findings applicables pour un système donné
 */
export function selectFindingsForSystem(system: DetectedSystem, findings: FindingEntry[] = FindingsLibrary): FindingEntry[] {
  return findings.filter(f => {
    if (!f.appliesTo) return true;
    
    // Vérifier la famille d'OS
    if (f.appliesTo.osFamily && !f.appliesTo.osFamily.includes(system.osFamily)) {
      return false;
    }
    
    // Vérifier l'édition
    if (f.appliesTo.editions && system.osEdition) {
      if (!f.appliesTo.editions.includes(system.osEdition)) {
        return false;
      }
    }
    
    // Vérifier le fabricant
    if (f.appliesTo.manufacturers && system.manufacturer) {
      const mfr = system.manufacturer.toLowerCase();
      if (!f.appliesTo.manufacturers.some(m => mfr.includes(m.toLowerCase()))) {
        return false;
      }
    }
    
    // Vérifier le build number
    if (f.appliesTo.minBuild && system.buildNumber) {
      if (parseInt(system.buildNumber) < parseInt(f.appliesTo.minBuild)) {
        return false;
      }
    }
    if (f.appliesTo.maxBuild && system.buildNumber) {
      if (parseInt(system.buildNumber) > parseInt(f.appliesTo.maxBuild)) {
        return false;
      }
    }
    
    return true;
  });
}

/**
 * Obtient la meilleure remédiation pour un finding et un système donnés
 */
export function getRemediationForFinding(finding: FindingEntry, system: DetectedSystem): RemediationVariant | null {
  if (!finding.remediationVariants || finding.remediationVariants.length === 0) {
    // Retourner une remédiation par défaut si pas de variants
    if (finding.remediation) {
      return {
        method: 'Note',
        instruction: finding.remediation
      };
    }
    return null;
  }
  
  const variants = finding.remediationVariants;
  let bestMatch: RemediationVariant | null = null;
  let bestScore = -1;
  
  for (const variant of variants) {
    let score = 0;
    
    // Score par édition (priorité haute)
    if (variant.edition && system.osEdition) {
      if (variant.edition.toLowerCase() === system.osEdition.toLowerCase()) {
        score += 100;
      }
    }
    
    // Score par fabricant (priorité moyenne)
    if (variant.manufacturer && system.manufacturer) {
      if (system.manufacturer.toLowerCase().includes(variant.manufacturer.toLowerCase())) {
        score += 50;
      }
    }
    
    // Score par OS (priorité basse)
    if (variant.osFamily && variant.osFamily === system.osFamily) {
      score += 10;
    }
    
    // Vérifier les builds si spécifiés
    if (variant.minBuild && system.buildNumber) {
      if (parseInt(system.buildNumber) < parseInt(variant.minBuild)) {
        continue; // Skip cette variante
      }
    }
    if (variant.maxBuild && system.buildNumber) {
      if (parseInt(system.buildNumber) > parseInt(variant.maxBuild)) {
        continue; // Skip cette variante
      }
    }
    
    // Si pas de critères spécifiques, c'est un fallback
    if (!variant.edition && !variant.manufacturer && !variant.osFamily) {
      score = 1; // Score minimal pour fallback
    }
    
    if (score > bestScore) {
      bestScore = score;
      bestMatch = variant;
    }
  }
  
  // Si aucun match, retourner le premier variant comme fallback
  return bestMatch || variants[0] || null;
}

/**
 * Génère un rapport de findings avec remédiations pour un système
 */
export function generateFindingsReport(system: DetectedSystem, findings?: FindingEntry[]) {
  const applicableFindings = selectFindingsForSystem(system, findings);
  
  return applicableFindings.map(finding => ({
    ...finding,
    suggestedRemediation: getRemediationForFinding(finding, system)
  }));
}

// ============================================
// CHARGEMENT DES BASELINES (Node.js only)
// ============================================

/**
 * Charge les baselines JSON depuis le dossier data/baselines
 */
export function loadBaselinesFromDisk(): FindingEntry[] {
  if (typeof window !== 'undefined') {
    console.warn('loadBaselinesFromDisk ne peut pas être appelé côté client');
    return [];
  }
  
  try {
    const fs = require('fs');
    const path = require('path');
    const baselinesDir = path.join(process.cwd(), 'data', 'baselines');
    
    if (!fs.existsSync(baselinesDir)) {
      console.warn('Dossier baselines non trouvé:', baselinesDir);
      return [];
    }
    
    const allFindings: FindingEntry[] = [];
    
    // Parcourir les sous-dossiers (windows, linux, macos)
    const subDirs = fs.readdirSync(baselinesDir, { withFileTypes: true })
      .filter((d: any) => d.isDirectory())
      .map((d: any) => d.name);
    
    for (const subDir of subDirs) {
      const subPath = path.join(baselinesDir, subDir);
      const files = fs.readdirSync(subPath).filter((f: string) => f.endsWith('.json'));
      
      for (const file of files) {
        try {
          const content = fs.readFileSync(path.join(subPath, file), 'utf8');
          const data = JSON.parse(content);
          
          if (Array.isArray(data)) {
            allFindings.push(...data);
          } else if (data.findings && Array.isArray(data.findings)) {
            allFindings.push(...data.findings);
          }
        } catch (e) {
          console.warn(`Erreur chargement baseline ${file}:`, e);
        }
      }
    }
    
    return allFindings;
  } catch (e) {
    console.error('Erreur chargement baselines:', e);
    return [];
  }
}

/**
 * Détermine le fichier baseline approprié pour un système
 */
export function pickBaselineFilename(system: DetectedSystem): string {
  if (system.osFamily === 'Windows') {
    const build = parseInt(system.buildNumber || '0');
    
    // Windows 11 24H2 (build >= 26100)
    if (build >= 26100) {
      return 'msft_windows_11_24h2_machine.json';
    }
    // Windows 11 22H2/23H2 (build >= 22621)
    if (build >= 22621) {
      return 'msft_windows_11_22h2_machine.json';
    }
    // Windows 10 22H2
    if (system.osVersion === '10' || build < 22000) {
      return 'msft_windows_10_22h2_machine.json';
    }
    // Default Windows 11
    return 'msft_windows_11_22h2_machine.json';
  }
  
  if (system.osFamily === 'Linux') {
    return 'linux_ubuntu_cis.json';
  }
  
  if (system.osFamily === 'macOS') {
    return 'macos_cis.json';
  }
  
  return '';
}

// Export default pour compatibilité
export default {
  FindingsLibrary,
  detectSystem,
  selectFindingsForSystem,
  getRemediationForFinding,
  generateFindingsReport,
  getWindowsDetectionCommands,
  parseWindowsDetection,
  loadBaselinesFromDisk,
  pickBaselineFilename
};
