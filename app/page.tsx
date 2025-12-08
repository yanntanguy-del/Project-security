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

// Fonction pour traduire les noms des findings en français
const translateFindingName = (name: string): string => {
  const translations: Record<string, string> = {
    // =====================================
    // === WINDOWS - POLITIQUES DE COMPTE ===
    // =====================================
    "Account lockout duration": "Durée de verrouillage du compte",
    "Account lockout threshold": "Seuil de verrouillage du compte",
    "Allow Administrator account lockout": "Autoriser le verrouillage du compte Administrateur",
    "Length of password history maintained": "Historique des mots de passe conservés",
    "Minimum password length": "Longueur minimale du mot de passe",
    "Password must meet complexity requirements": "Le mot de passe doit respecter les exigences de complexité",
    "Store passwords using reversible encryption": "Stocker les mots de passe avec chiffrement réversible",
    "Reset account lockout counter after": "Réinitialiser le compteur de verrouillage après",
    "Enforce password history": "Appliquer l'historique des mots de passe",
    "Maximum password age": "Durée de vie maximale du mot de passe",
    "Minimum password age": "Durée de vie minimale du mot de passe",
    
    // === WINDOWS - OPTIONS DE SÉCURITÉ ===
    "Accounts: Limit local account use of blank passwords to console logon only": "Limiter les mots de passe vides à la connexion console",
    "Interactive logon: Machine inactivity limit": "Limite d'inactivité de la machine",
    "Microsoft network client: Digitally sign communications (always)": "Client réseau : Signer numériquement les communications",
    "Microsoft network server: Digitally sign communications (always)": "Serveur réseau : Signer numériquement les communications",
    "Network security: Do not store LAN Manager hash value": "Ne pas stocker la valeur de hachage LAN Manager",
    "Network security: LAN Manager authentication level": "Niveau d'authentification LAN Manager",
    "Network access: Do not allow anonymous enumeration of SAM accounts": "Interdire l'énumération anonyme des comptes SAM",
    "Network access: Do not allow anonymous enumeration of SAM accounts and shares": "Interdire l'énumération anonyme des comptes et partages",
    "Network security: LDAP client signing requirements": "Exigences de signature du client LDAP",
    "Audit: Force audit policy subcategory settings": "Forcer les paramètres de sous-catégorie d'audit",
    
    // === WINDOWS - UAC ===
    "User Account Control: Admin Approval Mode for Built-in Administrator": "UAC : Mode d'approbation admin pour l'Administrateur intégré",
    "User Account Control: Behavior of elevation prompt for administrators": "UAC : Comportement de l'invite d'élévation pour les admins",
    "User Account Control: Run all administrators in Admin Approval Mode": "UAC : Exécuter tous les admins en mode d'approbation",
    "User Account Control: Behavior for administrators with Administrator protection": "UAC : Comportement avec protection Administrateur",
    "User Account Control: Configure type of Admin Approval Mode": "UAC : Configurer le type de mode d'approbation",
    "User Account Control: Admin Approval Mode for the Built-in Administrator account": "UAC : Mode d'approbation admin pour le compte Administrateur",
    "User Account Control: Behavior of the elevation prompt for administrators": "UAC : Comportement de l'invite d'élévation pour les administrateurs",
    "User Account Control: Behavior of the elevation prompt for standard users": "UAC : Comportement de l'invite d'élévation pour les utilisateurs",
    "User Account Control: Detect application installations and prompt for elevation": "UAC : Détecter les installations et demander l'élévation",
    
    // === WINDOWS - PARE-FEU ===
    "EnableFirewall (Domain Profile)": "Activer le pare-feu (Profil Domaine)",
    "EnableFirewall (Private Profile)": "Activer le pare-feu (Profil Privé)",
    "EnableFirewall (Public Profile)": "Activer le pare-feu (Profil Public)",
    "Windows Firewall: Domain: Firewall state": "Pare-feu Windows : État (Domaine)",
    "Windows Firewall: Private: Firewall state": "Pare-feu Windows : État (Privé)",
    "Windows Firewall: Public: Firewall state": "Pare-feu Windows : État (Public)",
    
    // === WINDOWS - SMB ET RÉSEAU ===
    "Configure SMB v1 client driver": "Configurer le pilote client SMB v1",
    "Configure SMB v1 server": "Configurer le serveur SMB v1",
    "WDigest Authentication": "Authentification WDigest",
    "DNS Client: Turn off multicast name resolution (LLMNR)": "Désactiver la résolution de noms multicast (LLMNR)",
    "Turn off multicast name resolution": "Désactiver la résolution de noms multicast (LLMNR)",
    "Enable insecure guest logons": "Activer les connexions invité non sécurisées",
    "Lanman Workstation: Enable insecure guest logons": "Activer les connexions invité non sécurisées",
    "WLAN Settings: Auto-connect to suggested open hotspots": "Connexion auto aux hotspots Wi-Fi suggérés",
    "DNS Client: Configure NetBIOS settings": "Configurer les paramètres NetBIOS",
    "Hardened UNC Paths": "Chemins UNC renforcés",
    
    // === WINDOWS - MSS ET PROTECTIONS LEGACY ===
    "Enable Structured Exception Handling Overwrite Protection (SEHOP)": "Activer la protection SEHOP",
    "NetBT NodeType configuration": "Configuration du type de nœud NetBT",
    "MSS: DisableIPSourceRouting IPv6": "Désactiver le routage source IPv6",
    "MSS: DisableIPSourceRouting IPv4": "Désactiver le routage source IPv4",
    "MSS: EnableICMPRedirect - Allow ICMP redirects": "Autoriser les redirections ICMP",
    
    // === WINDOWS - DEVICE GUARD ET VBS ===
    "Configure the behavior of the sudo command": "Configurer le comportement de la commande sudo",
    "Device Guard: Turn On Virtualization Based Security": "Activer la sécurité basée sur la virtualisation (VBS)",
    "Device Guard: Virtualization Based Protection of Code Integrity": "Protection de l'intégrité du code par VBS (HVCI)",
    "Device Guard: Credential Guard Configuration": "Configuration de Credential Guard",
    "Device Guard: Kernel-mode Hardware-enforced Stack Protection": "Protection matérielle de la pile en mode noyau",
    "Local Security Authority: Configures LSASS to run as a protected process": "Configurer LSASS en processus protégé",
    "Turn On Virtualization Based Security": "Activer la sécurité basée sur la virtualisation (VBS)",
    "Virtualization Based Security": "Sécurité basée sur la virtualisation (VBS)",
    "Credential Guard Configuration": "Configuration de Credential Guard",
    "UEFI lock": "Verrouillage UEFI",
    
    // === WINDOWS - AUTOPLAY ET USB ===
    "AutoPlay Policies: Turn off Autoplay": "Désactiver l'exécution automatique",
    "AutoPlay Policies: Disallow Autoplay for non-volume devices": "Désactiver l'autoplay pour les appareils non-volume",
    "AutoPlay Policies: Set default behavior for AutoRun": "Définir le comportement par défaut d'AutoRun",
    "BitLocker: Disable new DMA devices when computer is locked": "BitLocker : Désactiver les appareils DMA quand verrouillé",
    
    // === WINDOWS - SMARTSCREEN ET DEFENDER ===
    "File Explorer: Configure Windows Defender SmartScreen": "Configurer Windows Defender SmartScreen",
    "Microsoft Defender Antivirus: Configure detection for PUA": "Configurer la détection des applications indésirables (PUA)",
    "Microsoft Defender Antivirus: MAPS: Join Microsoft MAPS": "Rejoindre Microsoft MAPS (protection cloud)",
    "Microsoft Defender Antivirus: Network Protection": "Protection réseau de Microsoft Defender",
    "Microsoft Defender: Scan all downloaded files and attachments": "Analyser tous les fichiers téléchargés",
    "Microsoft Defender: Turn off real-time protection": "Ne pas désactiver la protection en temps réel",
    "Windows Defender SmartScreen: Enhanced Phishing Protection": "Protection anti-hameçonnage améliorée",
    "Configure detection for potentially unwanted applications": "Configurer la détection des applications indésirables (PUA)",
    "Join Microsoft MAPS": "Rejoindre Microsoft MAPS (protection cloud)",
    "Configure the 'Block at First Sight' feature": "Activer le blocage à la première vue",
    "Send file samples when further analysis is required": "Envoyer des échantillons pour analyse",
    "Turn on real-time protection": "Activer la protection en temps réel",
    "Turn on behavior monitoring": "Activer la surveillance comportementale",
    "Scan all downloaded files and attachments": "Analyser tous les fichiers téléchargés",
    "Turn on script scanning": "Activer l'analyse des scripts",
    "Configure Attack Surface Reduction rules": "Configurer les règles ASR",
    "Turn on network protection": "Activer la protection réseau",
    "Prevent users and apps from accessing dangerous websites": "Bloquer l'accès aux sites web dangereux",
    
    // === WINDOWS - POWERSHELL ===
    "Windows PowerShell: Turn on PowerShell Script Block Logging": "Activer la journalisation des scripts PowerShell",
    "Turn on PowerShell Script Block Logging (Invocation)": "Activer la journalisation d'invocation PowerShell",
    
    // === WINDOWS - WINRM ===
    "WinRM Client: Allow Basic authentication": "Client WinRM : Autoriser l'authentification basique",
    "WinRM Client: Allow unencrypted traffic": "Client WinRM : Autoriser le trafic non chiffré",
    "WinRM Client: Disallow Digest authentication": "Client WinRM : Interdire l'authentification Digest",
    "WinRM Service: Allow Basic authentication": "Service WinRM : Autoriser l'authentification basique",
    "WinRM Service: Allow unencrypted traffic": "Service WinRM : Autoriser le trafic non chiffré",
    "WinRM Service: Disallow WinRM from storing RunAs credentials": "Service WinRM : Interdire le stockage des identifiants",
    
    // === WINDOWS - BUREAU À DISTANCE ===
    "Remote Desktop: Do not allow passwords to be saved": "Bureau à distance : Ne pas enregistrer les mots de passe",
    "Remote Desktop: Require secure RPC communication": "Bureau à distance : Exiger une communication RPC sécurisée",
    "Remote Desktop: Set client connection encryption level": "Bureau à distance : Niveau de chiffrement élevé",
    
    // === WINDOWS - SERVICES XBOX ===
    "Xbox Accessory Management Service (XboxGipSvc)": "Service de gestion des accessoires Xbox",
    "Xbox Live Auth Manager (XblAuthManager)": "Gestionnaire d'authentification Xbox Live",
    "Xbox Live Game Save (XblGameSave)": "Sauvegarde de jeux Xbox Live",
    "Xbox Live Networking Service (XboxNetApiSvc)": "Service réseau Xbox Live",
    "Xbox Accessory Management Service": "Service de gestion des accessoires Xbox",
    "Xbox Live Auth Manager": "Gestionnaire d'authentification Xbox Live",
    "Xbox Live Game Save": "Sauvegarde de jeux Xbox Live",
    "Xbox Live Networking Service": "Service réseau Xbox Live",
    
    // === WINDOWS - ASR (ATTACK SURFACE REDUCTION) ===
    "Block executable content from email client and webmail": "Bloquer le contenu exécutable des emails",
    "Block Office applications from creating child processes": "Empêcher Office de créer des processus enfants",
    "Block credential stealing from LSASS": "Bloquer le vol d'identifiants depuis LSASS",
    "Block JavaScript/VBScript from launching downloaded content": "Bloquer JS/VBScript de lancer du contenu téléchargé",
    "Use advanced protection against ransomware": "Activer la protection avancée contre les ransomwares",
    "Block Office applications from creating executable content": "Empêcher Office de créer du contenu exécutable",
    "Block Office applications from injecting code into other processes": "Empêcher Office d'injecter du code",
    "Block Win32 API calls from Office macros": "Bloquer les appels Win32 depuis les macros Office",
    "Block execution of potentially obfuscated scripts": "Bloquer l'exécution de scripts obfusqués",
    "Block untrusted and unsigned processes that run from USB": "Bloquer les processus non signés depuis USB",
    "Block Adobe Reader from creating child processes": "Empêcher Adobe Reader de créer des processus enfants",
    "Block persistence through WMI event subscription": "Bloquer la persistance via WMI",
    "Block all Office applications from creating child processes": "Empêcher Office de créer des processus enfants",
    "Block JavaScript or VBScript from launching downloaded executable content": "Bloquer JavaScript/VBScript de lancer des exécutables",
    "Block executable files from running unless they meet a prevalence, age, or trusted list criterion": "Bloquer les exécutables non fiables",
    "Block credential stealing from the Windows local security authority subsystem": "Bloquer le vol d'identifiants depuis LSASS",
    "Block process creations originating from PSExec and WMI commands": "Bloquer les processus créés via PSExec et WMI",
    "Block Office communication application from creating child processes": "Empêcher Outlook de créer des processus enfants",
    "Block abuse of exploited vulnerable signed drivers": "Bloquer l'abus de pilotes signés vulnérables",
    
    // === WINDOWS - AUTRES PARAMÈTRES ===
    "Cloud Content: Turn off Microsoft consumer experiences": "Désactiver les expériences consommateur Microsoft",
    "Windows Installer: Allow user control over installs": "Contrôle utilisateur sur les installations",
    "Windows Installer: Always install with elevated privileges": "Toujours installer avec des privilèges élevés",
    "Windows Logon Options: Disable automatic restart sign-on": "Désactiver la reconnexion automatique après redémarrage",
    "Apply UAC restrictions to local accounts on network logons": "Appliquer les restrictions UAC aux comptes locaux réseau",
    "Search: Allow indexing of encrypted files": "Autoriser l'indexation des fichiers chiffrés",
    
    // === WINDOWS - BITLOCKER ===
    "BitLocker Drive Encryption": "Chiffrement de lecteur BitLocker",
    "Require additional authentication at startup": "Exiger une authentification supplémentaire au démarrage",
    
    // === WINDOWS - TÉLÉMÉTRIE ===
    "Allow Telemetry": "Autoriser la télémétrie",
    "Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service": "Configurer le proxy pour la télémétrie",
    
    // === WINDOWS - ÉCRAN DE VERROUILLAGE ===
    "Interactive logon: Message text for users attempting to log on": "Message de connexion pour les utilisateurs",
    "Interactive logon: Message title for users attempting to log on": "Titre du message de connexion",

    // =====================================
    // === macOS - PROTECTION SYSTÈME ===
    // =====================================
    "System Integrity Protection (SIP)": "Protection de l'intégrité du système (SIP)",
    "Gatekeeper Status": "État de Gatekeeper",
    "XProtect Status": "État de XProtect",
    "MRT (Malware Removal Tool)": "Outil de suppression des malwares (MRT)",
    "Lockdown Mode Available": "Mode Isolement disponible",
    "Secure Enclave Status": "État du Secure Enclave",
    "Kernel Integrity Protection": "Protection de l'intégrité du kernel",
    "Pointer Authentication (PAC)": "Authentification des pointeurs (PAC)",
    "T2 Security Chip": "Puce de sécurité T2",
    
    // === macOS - FILEVAULT ===
    "FileVault Disk Encryption": "Chiffrement de disque FileVault",
    "FileVault Recovery Key": "Clé de récupération FileVault",
    
    // === macOS - PARE-FEU ===
    "Application Firewall Status": "État du pare-feu applicatif",
    "Firewall Stealth Mode": "Mode furtif du pare-feu",
    "Block All Incoming Connections": "Bloquer toutes les connexions entrantes",
    
    // === macOS - VERROUILLAGE ÉCRAN ===
    "Require Password After Sleep/Screensaver": "Mot de passe requis après veille/économiseur",
    "Password Delay After Sleep": "Délai avant demande de mot de passe",
    "Auto Logout Idle Time": "Déconnexion automatique après inactivité",
    
    // === macOS - ACCÈS À DISTANCE ===
    "SSH Remote Login": "Connexion SSH à distance",
    "Screen Sharing": "Partage d'écran",
    "Remote Apple Events": "Événements Apple distants",
    "Remote Management (ARD)": "Gestion à distance (ARD)",
    "iPhone Mirroring Control": "Contrôle de la recopie iPhone",
    
    // === macOS - CONFIDENTIALITÉ ===
    "Location Services": "Services de localisation",
    "Analytics Sharing": "Partage des analyses",
    "Personalized Ads": "Publicités personnalisées",
    "App Privacy Report": "Rapport de confidentialité des apps",
    
    // === macOS - MISES À JOUR ===
    "Automatic Updates Check": "Vérification auto des mises à jour",
    "Download New Updates": "Téléchargement des mises à jour",
    "Install macOS Updates": "Installation des mises à jour macOS",
    "Install Security Responses": "Installation des correctifs de sécurité rapides",
    
    // === macOS - SAFARI ===
    "Safari Fraudulent Sites Warning": "Alerte sites frauduleux Safari",
    "Safari Private Browsing by Default": "Navigation privée Safari par défaut",
    
    // === macOS - RÉSEAU ===
    "Bluetooth Status": "État du Bluetooth",
    "AirDrop Mode": "Mode AirDrop",
    
    // === macOS - COMPTES UTILISATEUR ===
    "Guest Account Status": "État du compte invité",
    "Touch ID / Face ID": "Touch ID / Face ID",
    
    // === macOS - iCLOUD ===
    "Advanced Data Protection": "Protection avancée des données",
    "Find My Mac": "Localiser mon Mac",
    "Passwords App Security": "Sécurité de l'app Mots de passe",
    
    // === macOS - DÉMARRAGE ===
    "Secure Boot Level": "Niveau de démarrage sécurisé",
    "Window Tiling Permissions": "Permissions du tiling de fenêtres",
    
    // === macOS - TERMINAL ===
    "Terminal Secure Keyboard Entry": "Saisie clavier sécurisée Terminal",
    
    // === macOS - APPLE INTELLIGENCE ===
    "Apple Intelligence Privacy": "Confidentialité Apple Intelligence",
    "Private Cloud Compute": "Calcul cloud privé",

    // =====================================
    // === LINUX - INTÉGRITÉ SYSTÈME ===
    // =====================================
    "AIDE Installed": "AIDE installé",
    "Pacman GPG Verification": "Vérification GPG de Pacman",
    
    // === LINUX - DÉMARRAGE ===
    "GRUB Password": "Mot de passe GRUB",
    "Secure Boot": "Démarrage sécurisé (Secure Boot)",
    "Systemd-boot Secure": "Sécurité systemd-boot",
    
    // === LINUX - MAC (CONTRÔLE D'ACCÈS) ===
    "AppArmor Status": "État d'AppArmor",
    "AppArmor Profiles Enforced": "Profils AppArmor appliqués",
    "SELinux Status": "État de SELinux",
    "SELinux Policy": "Politique SELinux",
    
    // === LINUX - COMPTES UTILISATEUR ===
    "Password Minimum Length": "Longueur minimale du mot de passe",
    "Password Complexity": "Complexité du mot de passe",
    "Password Maximum Age": "Durée maximale du mot de passe",
    "Empty Passwords Check": "Vérification des mots de passe vides",
    "UID 0 Accounts": "Comptes avec UID 0",
    "Sudo Configuration": "Configuration sudo",
    "Password Policy": "Politique de mot de passe",
    
    // === LINUX - PARTITIONS ===
    "Separate /tmp Partition": "Partition /tmp séparée",
    "Separate /var Partition": "Partition /var séparée",
    "Separate /var/log Partition": "Partition /var/log séparée",
    "Separate /home Partition": "Partition /home séparée",
    
    // === LINUX - SSH ===
    "SSH Protocol Version": "Version du protocole SSH",
    "SSH Root Login": "Connexion root SSH",
    "SSH Password Authentication": "Authentification SSH par mot de passe",
    "SSH Password Auth": "Authentification SSH par mot de passe",
    "SSH Empty Passwords": "Mots de passe SSH vides",
    "SSH X11 Forwarding": "Transfert X11 SSH",
    "SSH Max Auth Tries": "Tentatives max d'authentification SSH",
    "SSH Login Grace Time": "Délai de grâce connexion SSH",
    "SSH Client Alive Interval": "Intervalle de vérification client SSH",
    
    // === LINUX - PARE-FEU ===
    "UFW Status": "État d'UFW",
    "UFW Default Incoming": "Politique UFW entrante par défaut",
    "iptables Installed": "iptables installé",
    "iptables Status": "État d'iptables",
    "nftables Status": "État de nftables",
    "Firewalld Status": "État de Firewalld",
    "Firewalld Default Zone": "Zone Firewalld par défaut",
    
    // === LINUX - SERVICES ===
    "Unnecessary Services": "Services non nécessaires",
    "xinetd Service": "Service xinetd",
    "rsh Services": "Services rsh",
    "telnet Server": "Serveur telnet",
    "Fail2ban Service": "Service Fail2ban",
    
    // === LINUX - ENVIRONNEMENT BUREAU ===
    "GNOME Auto-mount": "Montage automatique GNOME",
    "GNOME Screen Lock": "Verrouillage écran GNOME",
    "Screen Lock Timeout": "Délai de verrouillage écran",
    
    // === LINUX - DURCISSEMENT NOYAU ===
    "ASLR Status": "État de l'ASLR",
    "ASLR": "ASLR (Randomisation de l'espace d'adressage)",
    "Kernel Pointer Hiding": "Masquage des pointeurs noyau",
    "Dmesg Restrictions": "Restrictions dmesg",
    "SYN Flood Protection": "Protection contre les attaques SYN flood",
    "IP Forwarding": "Transfert IP",
    "ICMP Redirect Accept": "Acceptation des redirections ICMP",
    "Source Route Packets": "Paquets routés à la source",
    "Log Martian Packets": "Journalisation des paquets martiens",
    "Hardened Kernel": "Noyau durci",
    
    // === LINUX - PERMISSIONS FICHIERS ===
    "/etc/passwd Permissions": "Permissions de /etc/passwd",
    "/etc/shadow Permissions": "Permissions de /etc/shadow",
    "/etc/gshadow Permissions": "Permissions de /etc/gshadow",
    "SUID Files Audit": "Audit des fichiers SUID",
    "World-Writable Files": "Fichiers modifiables par tous",
    
    // === LINUX - JOURNALISATION ===
    "Rsyslog Installed": "Rsyslog installé",
    "Journald Persistent Storage": "Stockage persistant de Journald",
    "Systemd Journal Persistent": "Journal Systemd persistant",
    "Auditd Service": "Service Auditd",
    "Auditd": "Service d'audit Auditd",
    
    // === LINUX - MISES À JOUR ===
    "Automatic Security Updates": "Mises à jour de sécurité automatiques",
    "Package Signature Verification": "Vérification des signatures de paquets",
    "Unattended Upgrades": "Mises à jour automatiques",
    "DNF Automatic": "DNF automatique",
    "System Updated": "Système à jour",
    "Pacman Mirrors Updated": "Miroirs Pacman à jour",
    
    // === LINUX - CRON ===
    "Crontab Permissions": "Permissions de crontab",
    "At Daemon Access": "Accès au démon at",
    
    // === LINUX - CHIFFREMENT ===
    "LUKS Disk Encryption": "Chiffrement de disque LUKS",
    "Swap Encryption": "Chiffrement du swap",
    
    // === LINUX - ARCH SPÉCIFIQUE ===
    "AUR Helper PKGBUILD Review": "Révision des PKGBUILD AUR",
  };
  
  // Chercher une traduction exacte
  if (translations[name]) {
    return translations[name];
  }
  
  // Sinon retourner le nom original
  return name;
};

// Fonction pour générer une explication simple et accessible
const getSimpleExplanation = (finding: Finding): string => {
  const name = (finding.name || "").toLowerCase();
  const category = (finding.category || "").toLowerCase();
  const description = (finding.description || "").toLowerCase();

  // D'abord, vérifier les mots-clés spécifiques pour générer une explication adaptée
  // Cela permet d'avoir des explications cohérentes même si la description existe

  // === RANSOMWARE ===
  if (name.includes("ransomware") || description.includes("ransomware")) {
    return "Les ransomwares sont des virus qui chiffrent (verrouillent) tous vos fichiers personnels et demandent une rançon pour les récupérer. Cette protection détecte et bloque ces attaques avant qu'elles ne puissent endommager vos documents, photos et fichiers importants.";
  }

  // === WINDOWS DEFENDER / ANTIVIRUS ===
  if (name.includes("attack surface reduction") || name.includes("asr") || category.includes("asr")) {
    return "Cette protection bloque les techniques couramment utilisées par les virus et logiciels malveillants pour infecter votre ordinateur. C'est comme fermer les portes dérobées que les pirates utilisent.";
  }
  if (name.includes("pua") || name.includes("potentially unwanted")) {
    return "Cette fonctionnalité détecte et bloque les logiciels indésirables qui ne sont pas des virus mais qui peuvent ralentir votre PC, afficher des publicités ou espionner vos activités.";
  }
  if (name.includes("maps") || (name.includes("cloud") && name.includes("protection"))) {
    return "Votre antivirus peut envoyer des informations sur les fichiers suspects à Microsoft pour vérifier s'ils sont dangereux. C'est comme demander un deuxième avis à un expert en temps réel.";
  }
  if (name.includes("realtime") || name.includes("real-time") || name.includes("temps réel")) {
    return "L'antivirus surveille en permanence votre ordinateur pour détecter les menaces dès qu'elles apparaissent, plutôt que d'attendre un scan manuel.";
  }
  if (name.includes("behavior") || name.includes("comportement")) {
    return "Au lieu de chercher des virus connus, cette protection surveille les comportements suspects des programmes. Si un programme agit comme un virus, il est bloqué même s'il est inconnu.";
  }
  if (name.includes("script") && (name.includes("scan") || name.includes("block"))) {
    return "Les scripts sont de petits programmes qui peuvent s'exécuter dans votre navigateur ou vos documents Office. Cette protection analyse et bloque les scripts malveillants qui tentent d'infecter votre PC.";
  }
  if (name.includes("network protection") || name.includes("protection réseau")) {
    return "Cette protection empêche votre ordinateur de se connecter à des sites web dangereux connus pour distribuer des virus ou voler des informations.";
  }
  if (name.includes("exploit") && name.includes("protection")) {
    return "Les exploits sont des techniques qui profitent des failles de sécurité dans vos logiciels. Cette protection rend ces attaques beaucoup plus difficiles.";
  }
  if (name.includes("controlled folder") || name.includes("dossier contrôlé")) {
    return "Cette protection empêche les programmes non autorisés de modifier vos documents importants. Elle protège notamment contre les ransomwares qui chiffrent vos fichiers.";
  }
  if (name.includes("block at first") || name.includes("first seen")) {
    return "Quand Windows Defender rencontre un fichier inconnu et suspect, il peut le bloquer immédiatement le temps de vérifier s'il est dangereux. C'est une protection proactive contre les nouvelles menaces.";
  }
  if (name.includes("sample") && name.includes("submission")) {
    return "Windows peut envoyer automatiquement des fichiers suspects à Microsoft pour analyse. Cela aide à protéger tout le monde en détectant les nouvelles menaces plus rapidement.";
  }
  if (name.includes("office") && (name.includes("macro") || name.includes("child"))) {
    return "Les documents Office (Word, Excel) peuvent contenir des macros, de petits programmes qui sont souvent utilisés par les pirates. Cette protection empêche ces macros de faire des actions dangereuses.";
  }
  if (name.includes("adobe") || name.includes("pdf")) {
    return "Les fichiers PDF peuvent contenir du code malveillant. Cette protection empêche Adobe Reader de lancer des programmes dangereux cachés dans les PDF.";
  }
  if (name.includes("email") || name.includes("outlook")) {
    return "Les pièces jointes d'emails sont une source majeure d'infections. Cette protection analyse et bloque les contenus dangereux dans vos emails.";
  }
  if (name.includes("credential") && name.includes("steal")) {
    return "Les pirates utilisent des techniques pour voler vos mots de passe directement depuis la mémoire de Windows. Cette protection bloque ces tentatives de vol d'identifiants.";
  }
  if (name.includes("untrusted") || name.includes("unsigned")) {
    return "Les programmes non signés n'ont pas été vérifiés par leur éditeur. Cette protection bloque l'exécution de code non fiable qui pourrait être malveillant.";
  }
  if (name.includes("usb") || name.includes("removable")) {
    return "Les clés USB peuvent contenir des virus qui s'exécutent automatiquement. Cette protection empêche les programmes sur les supports amovibles de se lancer sans votre accord.";
  }
  if (name.includes("wmi") || name.includes("psexec") || name.includes("process creation")) {
    return "Les pirates utilisent des outils d'administration Windows pour propager leurs attaques. Cette protection bloque l'utilisation malveillante de ces outils système.";
  }

  // === MOTS DE PASSE ===
  if (name.includes("password") && (name.includes("length") || name.includes("longueur"))) {
    return "Plus un mot de passe est long, plus il est difficile à deviner. Un mot de passe de 14 caractères prendrait des millions d'années à craquer par un ordinateur.";
  }
  if (name.includes("password") && name.includes("complexity")) {
    return "Un mot de passe complexe mélange majuscules, minuscules, chiffres et symboles. C'est beaucoup plus difficile à deviner que 'motdepasse123'.";
  }
  if (name.includes("password") && name.includes("history")) {
    return "Windows se souvient de vos anciens mots de passe pour vous empêcher de réutiliser le même. Si un ancien mot de passe est compromis, vous ne pouvez pas y revenir.";
  }
  if (name.includes("lockout") && (name.includes("threshold") || name.includes("seuil"))) {
    return "Après un certain nombre de mots de passe incorrects, le compte se bloque. Cela empêche les pirates d'essayer des milliers de combinaisons.";
  }
  if (name.includes("lockout") && (name.includes("duration") || name.includes("durée"))) {
    return "Quand un compte est bloqué après trop de tentatives, il reste inaccessible pendant un certain temps. Cela ralentit considérablement les pirates.";
  }

  // === FIREWALL / PARE-FEU ===
  if (name.includes("firewall") || name.includes("pare-feu")) {
    return "Le pare-feu contrôle quels programmes peuvent communiquer avec Internet et qui peut se connecter à votre ordinateur. C'est comme un videur à l'entrée de votre PC.";
  }

  // === CHIFFREMENT / BITLOCKER ===
  if (name.includes("bitlocker")) {
    return "BitLocker chiffre tout votre disque dur. Si quelqu'un vole votre ordinateur, il ne pourra pas lire vos fichiers sans votre mot de passe.";
  }

  // === UAC ===
  if (name.includes("uac") || name.includes("user account control")) {
    return "L'UAC vous demande confirmation avant qu'un programme puisse faire des modifications importantes sur votre PC. Cela empêche les logiciels malveillants d'agir sans votre accord.";
  }

  // === SERVICES ===
  if (name.includes("xbox") || name.includes("game")) {
    return "Ce service est lié aux fonctionnalités gaming de Windows. Si vous ne jouez pas, le désactiver n'affecte rien et réduit la surface d'attaque.";
  }
  if (name.includes("remote") && (name.includes("desktop") || name.includes("bureau"))) {
    return "Le Bureau à distance permet de contrôler votre PC depuis un autre ordinateur. Si vous n'utilisez pas cette fonction, mieux vaut la désactiver pour éviter les intrusions.";
  }
  if (name.includes("telemetry") || name.includes("télémétrie")) {
    return "La télémétrie envoie des données d'utilisation à Microsoft. Réduire ce niveau protège votre vie privée tout en gardant les fonctionnalités essentielles.";
  }

  // === RÉSEAU ===
  if (name.includes("smb") || name.includes("server message block")) {
    return "SMB permet le partage de fichiers en réseau. Les anciennes versions (SMBv1) ont des failles de sécurité graves et doivent être désactivées.";
  }
  if (name.includes("guest") || name.includes("invité")) {
    return "Le compte invité permet à n'importe qui d'utiliser votre PC sans mot de passe. Le désactiver empêche les accès non autorisés.";
  }

  // === MISE À JOUR ===
  if (name.includes("update") || name.includes("mise à jour")) {
    return "Les mises à jour corrigent les failles de sécurité découvertes. Un ordinateur non mis à jour est vulnérable aux attaques connues.";
  }

  // === ÉCRAN / SESSION ===
  if (name.includes("inactivity") || name.includes("inactivité") || name.includes("lock") && name.includes("screen")) {
    return "Votre écran se verrouille automatiquement après un moment d'inactivité. Cela protège votre PC si vous oubliez de le verrouiller en partant.";
  }
  if (name.includes("screensaver") || name.includes("écran de veille")) {
    return "L'écran de veille peut demander un mot de passe au retour. C'est une protection si vous laissez votre ordinateur sans surveillance.";
  }

  // === CREDENTIAL GUARD / PROTECTION AVANCÉE ===
  if (name.includes("credential guard") || name.includes("protection des identifiants")) {
    return "Cette protection avancée isole vos mots de passe dans une zone sécurisée du processeur. Même si un pirate prend le contrôle de Windows, il ne peut pas voler vos identifiants.";
  }
  if (name.includes("lsass") || name.includes("local security authority")) {
    return "LSASS gère vos identifiants de connexion. Cette protection empêche les logiciels malveillants de voler vos mots de passe en mémoire.";
  }

  // === GÉNÉRAL PAR CATÉGORIE ===
  if (category.includes("account") || category.includes("compte")) {
    return "Ce paramètre contrôle la sécurité de votre compte utilisateur et protège contre les tentatives d'accès non autorisées.";
  }
  if (category.includes("defender") || category.includes("antivirus")) {
    return "Ce paramètre configure votre antivirus Windows Defender pour mieux protéger votre ordinateur contre les virus et logiciels malveillants.";
  }
  if (category.includes("security") || category.includes("sécurité")) {
    return "Ce paramètre renforce la sécurité générale de votre système Windows contre les menaces courantes.";
  }
  if (category.includes("privacy") || category.includes("confidentialité")) {
    return "Ce paramètre contrôle quelles informations votre ordinateur partage, protégeant ainsi votre vie privée.";
  }

  // Fallback - description générique si rien ne correspond
  return finding.description || "Ce paramètre de sécurité aide à protéger votre ordinateur contre les menaces. Activez-le pour renforcer votre protection.";
};

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
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // Fonction pour copier le code dans le presse-papiers
  const copyToClipboard = async (code: string, id: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(null), 2000);
    } catch (err) {
      console.error("Erreur lors de la copie:", err);
    }
  };

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
                      finding.severity === "Critical" || finding.severity === "Critique" ? "bg-red-500/20 text-red-400" :
                      finding.severity === "High" || finding.severity === "Élevée" ? "bg-orange-500/20 text-orange-400" :
                      finding.severity === "Medium" || finding.severity === "Moyenne" ? "bg-yellow-500/20 text-yellow-400" :
                      finding.severity === "Low" || finding.severity === "Faible" ? "bg-green-500/20 text-green-400" :
                      "bg-blue-500/20 text-blue-400"
                    }`}>
                      {finding.severity || "Moyenne"}
                    </span>
                  </div>
                  <p className="font-medium text-white truncate">{translateFindingName(finding.name)}</p>
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

                  {/* Description - Explication simple */}
                  <div className="mt-4 p-3 rounded-lg bg-blue-500/10 border border-blue-500/30">
                    <p className="text-xs text-blue-400 mb-2 font-semibold">💡 C'est quoi ?</p>
                    <p className="text-sm text-gray-300">{getSimpleExplanation(finding)}</p>
                  </div>

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
                        <div className="relative">
                          <button
                            onClick={() => copyToClipboard(finding.remediation as string, `${finding.id}-string`)}
                            className="absolute top-2 right-2 p-1.5 rounded bg-gray-700/50 hover:bg-gray-600/50 transition-colors z-10"
                            title="Copier le code"
                          >
                            {copiedCode === `${finding.id}-string` ? (
                              <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                              </svg>
                            ) : (
                              <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                              </svg>
                            )}
                          </button>
                          <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono bg-black/30 p-2 pr-10 rounded">
                            {finding.remediation}
                          </pre>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {finding.remediation.default && (
                            <div>
                              <p className="text-xs text-gray-500 mb-1">💻 Commande PowerShell :</p>
                              <div className="relative">
                                <button
                                  onClick={() => copyToClipboard(finding.remediation && typeof finding.remediation === 'object' ? finding.remediation.default || '' : '', `${finding.id}-powershell`)}
                                  className="absolute top-2 right-2 p-1.5 rounded bg-gray-700/50 hover:bg-gray-600/50 transition-colors z-10"
                                  title="Copier le code"
                                >
                                  {copiedCode === `${finding.id}-powershell` ? (
                                    <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                  ) : (
                                    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                  )}
                                </button>
                                <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono bg-black/30 p-2 pr-10 rounded">
                                  {finding.remediation.default}
                                </pre>
                              </div>
                            </div>
                          )}
                          {finding.remediation.gpo && scanResult?.system.osEdition !== "Home" && (
                            <div>
                              <p className="text-xs text-gray-500 mb-1">🏢 Stratégie de groupe (GPO) :</p>
                              <div className="relative">
                                <button
                                  onClick={() => copyToClipboard(finding.remediation && typeof finding.remediation === 'object' ? finding.remediation.gpo || '' : '', `${finding.id}-gpo`)}
                                  className="absolute top-2 right-2 p-1.5 rounded bg-gray-700/50 hover:bg-gray-600/50 transition-colors z-10"
                                  title="Copier le chemin GPO"
                                >
                                  {copiedCode === `${finding.id}-gpo` ? (
                                    <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                  ) : (
                                    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                  )}
                                </button>
                                <p className="text-sm text-cyan-300 bg-black/30 p-2 pr-10 rounded">
                                  {finding.remediation.gpo}
                                </p>
                              </div>
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
