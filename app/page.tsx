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

        // Page d'accueil complète et améliorée pour Vercel
        return (
          <div style={{ minHeight: "100vh", background: "linear-gradient(135deg, #0f0a1a 0%, #1a0a2e 50%, #0f172a 100%)", color: "#fff", fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif" }}>
            <div style={{ position: "fixed", top: 0, left: 0, width: "100%", height: "100%", zIndex: -1 }} />
            <header style={{ padding: "2rem", textAlign: "center", borderBottom: "1px solid rgba(139,92,246,0.2)", backdropFilter: "blur(10px)", background: "rgba(15,10,26,0.7)" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "1rem", marginBottom: "0.5rem" }}>
                <div style={{ width: 50, height: 50, background: "linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.5rem", boxShadow: "0 4px 20px rgba(139,92,246,0.4)" }}>🛡️</div>
                <h1 style={{ fontSize: "2rem", fontWeight: 700, background: "linear-gradient(135deg, #fff 0%, #c4b5fd 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>Security Scanner</h1>
              </div>
              <span style={{ color: "#a78bfa", fontSize: "0.875rem", fontWeight: 500 }}>Version 0.1.0</span>
            </header>
            <main style={{ maxWidth: 900, margin: "0 auto", padding: "4rem 2rem" }}>
              <section style={{ textAlign: "center", marginBottom: "3rem" }}>
                <h2 style={{ fontSize: "2.5rem", fontWeight: 700, marginBottom: "1.5rem", lineHeight: 1.2 }}>
                  Analysez et <span style={{ background: "linear-gradient(135deg, #8b5cf6 0%, #06b6d4 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>sécurisez</span><br />votre système
                </h2>
                <p style={{ fontSize: "1.25rem", color: "#94a3b8", maxWidth: 700, margin: "0 auto 2.5rem", lineHeight: 1.7 }}>
                  Security Scanner est un outil gratuit qui analyse votre ordinateur pour détecter les vulnérabilités et vous aide à appliquer les meilleures pratiques de sécurité.
                </p>
                <a href="https://github.com/yanntanguy-del/Project-security" target="_blank" rel="noopener" style={{ display: "inline-flex", alignItems: "center", gap: "0.75rem", padding: "1.25rem 3rem", fontSize: "1.125rem", fontWeight: 600, color: "#fff", background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);", border: "none", borderRadius: 16, cursor: "pointer", textDecoration: "none", transition: "all 0.3s ease", boxShadow: "0 4px 30px rgba(139,92,246,0.4)" }}>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" style={{ width: 24, height: 24 }}>
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  Accéder au dépôt GitHub
                </a>
                <p style={{ marginTop: "1rem", color: "#64748b", fontSize: "0.875rem" }}>Vous serez redirigé vers la page GitHub pour installer l'application</p>
              </section>
              <section style={{ marginBottom: "2rem" }}>
                <h2 style={{ textAlign: "center", fontSize: "1.5rem", fontWeight: 700, marginBottom: "1.5rem", color: "#fff" }}>Qu'est-ce que Security Scanner ?</h2>
                <div style={{ background: "rgba(139,92,246,0.05)", border: "1px solid rgba(139,92,246,0.2)", borderRadius: 20, padding: "2rem" }}>
                  <p style={{ color: "#94a3b8", lineHeight: 1.8, fontSize: "1.1rem", marginBottom: "1.5rem" }}>
                    <strong style={{ color: "#fff" }}>Security Scanner</strong> est une application qui analyse automatiquement les paramètres de sécurité de votre ordinateur. Elle vérifie plus de 100 configurations différentes : pare-feu, antivirus, politiques de mot de passe, et bien d'autres.
                  </p>
                  <p style={{ color: "#94a3b8", lineHeight: 1.8, fontSize: "1.1rem", marginBottom: "1.5rem" }}>
                    L'application génère un <strong style={{ color: "#fff" }}>rapport détaillé</strong> avec des codes couleur : <span style={{ color: "#22c55e" }}>vert</span> pour ce qui est conforme, <span style={{ color: "#ef4444" }}>rouge</span> pour ce qui nécessite attention, et <span style={{ color: "#eab308" }}>jaune</span> pour ce qui n'a pas pu être vérifié.
                  </p>
                  <p style={{ color: "#94a3b8", lineHeight: 1.8, fontSize: "1.1rem" }}>
                    Pour chaque problème détecté, vous recevez des <strong style={{ color: "#fff" }}>instructions claires</strong> pour corriger les vulnérabilités. L'interface est entièrement en français et conçue pour être compréhensible, même sans connaissances techniques.
                  </p>
                </div>
              </section>
              <section style={{ marginBottom: "2rem" }}>
                <div style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start", background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)", borderRadius: 16, padding: "1.5rem 2rem" }}>
                  <div style={{ fontSize: "2rem", flexShrink: 0 }}>ℹ️</div>
                  <div>
                    <h3 style={{ color: "#fff", fontSize: "1.125rem", marginBottom: "0.5rem" }}>Comment obtenir l'application ?</h3>
                    <p style={{ color: "#94a3b8", lineHeight: 1.6 }}>
                      Cliquez sur le bouton ci-dessus pour accéder au dépôt GitHub. Suivez les instructions sur la page pour télécharger et installer l'application sur votre ordinateur.
                    </p>
                  </div>
                </div>
              </section>
              <section style={{ marginBottom: "2rem" }}>
                <h2 style={{ textAlign: "center", fontSize: "1.5rem", fontWeight: 700, marginBottom: "1.5rem", color: "#fff" }}>Comment installer l'application ?</h2>
                <div style={{ display: "flex", flexDirection: "column", gap: "2rem", maxWidth: 700, margin: "0 auto" }}>
                  <div style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start" }}>
                    <div style={{ flexShrink: 0, width: 50, height: 50, background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.25rem", fontWeight: 700, boxShadow: "0 4px 20px rgba(139,92,246,0.4)" }}>1</div>
                    <div style={{ flex: 1, paddingTop: "0.5rem" }}>
                      <h4 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.5rem", color: "#fff" }}>Accédez au dépôt GitHub</h4>
                      <p style={{ color: "#94a3b8", lineHeight: 1.6 }}>
                        Cliquez sur le bouton "Accéder au dépôt GitHub" ci-dessus. Vous serez redirigé vers la page du projet.
                      </p>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start" }}>
                    <div style={{ flexShrink: 0, width: 50, height: 50, background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.25rem", fontWeight: 700, boxShadow: "0 4px 20px rgba(139,92,246,0.4)" }}>2</div>
                    <div style={{ flex: 1, paddingTop: "0.5rem" }}>
                      <h4 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.5rem", color: "#fff" }}>Téléchargez le fichier ZIP</h4>
                      <p style={{ color: "#94a3b8", lineHeight: 1.6 }}>
                        Sur la page GitHub, cliquez sur le bouton vert "Code" puis sélectionnez "Download ZIP" pour télécharger l'archive contenant l'application.
                      </p>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start" }}>
                    <div style={{ flexShrink: 0, width: 50, height: 50, background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.25rem", fontWeight: 700, boxShadow: "0 4px 20px rgba(139,92,246,0.4)" }}>3</div>
                    <div style={{ flex: 1, paddingTop: "0.5rem" }}>
                      <h4 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.5rem", color: "#fff" }}>Extrayez l'archive</h4>
                      <p style={{ color: "#94a3b8", lineHeight: 1.6 }}>
                        Une fois le fichier ZIP téléchargé, faites un clic droit dessus et sélectionnez "Extraire tout..." pour décompresser les fichiers dans un dossier de votre choix.
                      </p>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start" }}>
                    <div style={{ flexShrink: 0, width: 50, height: 50, background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.25rem", fontWeight: 700, boxShadow: "0 4px 20px rgba(139,92,246,0.4)" }}>4</div>
                    <div style={{ flex: 1, paddingTop: "0.5rem" }}>
                      <h4 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.5rem", color: "#fff" }}>Lancez l'application</h4>
                      <p style={{ color: "#94a3b8", lineHeight: 1.6 }}>
                        Ouvrez le dossier extrait et double-cliquez sur le fichier exécutable <strong>Security Scanner.exe</strong> pour démarrer l'application.
                      </p>
                    </div>
                  </div>
                </div>
              </section>
              <section style={{ textAlign: "center", background: "linear-gradient(135deg, rgba(139,92,246,0.1) 0%, rgba(99,102,241,0.1) 100%)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 24, padding: "2rem" }}>
                <h3 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "1rem", color: "#fff" }}>Prêt à sécuriser votre système ?</h3>
                <p style={{ color: "#94a3b8", marginBottom: "2rem", fontSize: "1.125rem" }}>Accédez au dépôt GitHub pour télécharger Security Scanner gratuitement.</p>
                <a href="https://github.com/yanntanguy-del/Project-security" target="_blank" rel="noopener" style={{ display: "inline-flex", alignItems: "center", gap: "0.75rem", padding: "1.25rem 3rem", fontSize: "1.125rem", fontWeight: 600, color: "#fff", background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)", border: "none", borderRadius: 16, cursor: "pointer", textDecoration: "none", transition: "all 0.3s ease", boxShadow: "0 4px 30px rgba(139,92,246,0.4)" }}>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" style={{ width: 24, height: 24 }}>
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  Accéder au dépôt GitHub
                </a>
              </section>
            </main>
            <footer style={{ textAlign: "center", padding: "2rem", borderTop: "1px solid rgba(139,92,246,0.2)", marginTop: "4rem", color: "#64748b", fontSize: "0.875rem" }}>
              <p>© 2025 Security Scanner. Outil d'analyse de sécurité.</p>
            </footer>
          </div>
        );
      }
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
