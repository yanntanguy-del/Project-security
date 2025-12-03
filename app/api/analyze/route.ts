// app/api/analyze/route.ts
import { NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";
import os from "os";

const execAsync = promisify(exec);

type DetectedSystem = {
  osFamily: "Windows" | "Linux" | "macOS" | "Unknown";
  osName?: string;
  osVersion?: string;
  osEdition?: string;
  buildNumber?: string;
  manufacturer?: string;
  model?: string;
  processor?: string;
  processorFeatures?: {
    supportsCET?: boolean;  // Control-flow Enforcement Technology
    supportsVBS?: boolean;  // Virtualization Based Security
  };
  // Champs spécifiques macOS
  chipType?: string; // "Apple Silicon" | "Intel"
  macModel?: string;
  // Champs spécifiques Linux
  distro?: string;
  distroVersion?: string;
  kernelVersion?: string;
  desktopEnvironment?: string;
  detectedAt: string;
};

type Finding = {
  id: string;
  name?: string;
  title?: string;
  category?: string;
  severity: string;
  description?: string;
  risk?: string;
  compatibility?: string;
  method?: string;
  methodArgument?: string;
  // Windows
  registryPath?: string;
  registryItem?: string;
  // macOS
  domain?: string;
  key?: string;
  command?: string;
  // Linux
  path?: string;
  pattern?: string;
  // Common
  defaultValue?: string;
  recommendedValue?: string;
  operator?: string;
  remediation?: any;
  status?: "pass" | "fail" | "unknown";
  currentValue?: string;
  skipReason?: "service_not_installed" | "manual_check" | "admin_required" | "not_compatible";
};

// ============================================================================
// DÉTECTION DU SYSTÈME D'EXPLOITATION
// ============================================================================

// Détecter les fonctionnalités du processeur
function detectProcessorFeatures(processorName: string, manufacturer: string): { supportsCET: boolean; supportsVBS: boolean } {
  const cpuLower = processorName.toLowerCase();
  const mfrLower = manufacturer.toLowerCase();
  
  let supportsCET = false;
  let supportsVBS = false;
  
  // Intel - CET supporté à partir de la 11e génération (Tiger Lake)
  if (mfrLower.includes("intel")) {
    // Chercher le numéro de génération dans le nom du CPU
    // Ex: "Intel(R) Core(TM) i7-1165G7" -> 11e gen
    // Ex: "Intel(R) Core(TM) i5-12400" -> 12e gen
    const genMatch = cpuLower.match(/i[3579]-(\d{2})/);
    if (genMatch) {
      const genNum = parseInt(genMatch[1].substring(0, 2));
      supportsCET = genNum >= 11;
      supportsVBS = genNum >= 6; // VBS supporté depuis ~6e gen
    }
    // Nouveau format Intel Core Ultra
    if (cpuLower.includes("ultra")) {
      supportsCET = true;
      supportsVBS = true;
    }
  }
  
  // AMD - CET supporté à partir de Zen 3 (Ryzen 5000 series)
  if (mfrLower.includes("amd")) {
    // Ex: "AMD Ryzen 7 5800X" -> Zen 3
    const ryzenMatch = cpuLower.match(/ryzen\s*\d+\s*(\d)/);
    if (ryzenMatch) {
      const series = parseInt(ryzenMatch[1]);
      supportsCET = series >= 5; // Ryzen 5000+ = Zen 3+
      supportsVBS = series >= 2; // Ryzen 2000+ supporte VBS
    }
  }
  
  return { supportsCET, supportsVBS };
}

// Détecter l'OS de la machine
function detectOSFamily(): "Windows" | "Linux" | "macOS" | "Unknown" {
  const platform = os.platform();
  if (platform === "win32") return "Windows";
  if (platform === "darwin") return "macOS";
  if (platform === "linux") return "Linux";
  return "Unknown";
}

// Détection Windows via PowerShell
async function detectWindowsSystem(): Promise<DetectedSystem> {
  const base: DetectedSystem = {
    osFamily: "Windows",
    detectedAt: new Date().toISOString(),
  };

  try {
    // Commande PowerShell pour récupérer toutes les infos système
    const psCommand = `$os = Get-CimInstance -ClassName Win32_OperatingSystem; $cs = Get-CimInstance -ClassName Win32_ComputerSystem; $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1; $edition = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').EditionID; @{Caption = $os.Caption; Version = $os.Version; BuildNumber = $os.BuildNumber; Edition = $edition; Manufacturer = $cs.Manufacturer; Model = $cs.Model; Processor = $cpu.Name; ProcessorManufacturer = $cpu.Manufacturer} | ConvertTo-Json -Compress`;

    const { stdout } = await execAsync(`powershell -NoProfile -Command "${psCommand}"`, {
      windowsHide: true,
    });

    const info = JSON.parse(stdout.trim());

    // Normaliser l'édition
    let normalizedEdition = info.Edition || "";
    if (normalizedEdition.toLowerCase().includes("home") || normalizedEdition === "Core") {
      normalizedEdition = "Home";
    } else if (normalizedEdition.toLowerCase().includes("pro")) {
      normalizedEdition = "Pro";
    } else if (normalizedEdition.toLowerCase().includes("enterprise")) {
      normalizedEdition = "Enterprise";
    } else if (normalizedEdition.toLowerCase().includes("education")) {
      normalizedEdition = "Education";
    }

    // Déterminer la version Windows
    let osVersion = "";
    const caption = info.Caption || "";
    if (caption.includes("11")) osVersion = "11";
    else if (caption.includes("10")) osVersion = "10";

    // Détecter les fonctionnalités du processeur
    const processorFeatures = detectProcessorFeatures(info.Processor || "", info.ProcessorManufacturer || "");

    return {
      ...base,
      osName: info.Caption,
      osVersion,
      osEdition: normalizedEdition,
      buildNumber: String(info.BuildNumber || ""),
      manufacturer: info.Manufacturer || "",
      model: info.Model || "",
      processor: info.Processor || "",
      processorFeatures,
    };
  } catch (error) {
    console.error("Erreur détection Windows:", error);
    return base;
  }
}

// Détection macOS via sw_vers et system_profiler
async function detectMacOSSystem(): Promise<DetectedSystem> {
  const base: DetectedSystem = {
    osFamily: "macOS",
    detectedAt: new Date().toISOString(),
  };

  try {
    // Récupérer les infos via sw_vers
    const { stdout: swVersOut } = await execAsync("sw_vers");
    const swVersLines = swVersOut.split("\n");
    
    let productName = "";
    let productVersion = "";
    let buildVersion = "";
    
    for (const line of swVersLines) {
      if (line.includes("ProductName:")) {
        productName = line.split(":")[1]?.trim() || "";
      } else if (line.includes("ProductVersion:")) {
        productVersion = line.split(":")[1]?.trim() || "";
      } else if (line.includes("BuildVersion:")) {
        buildVersion = line.split(":")[1]?.trim() || "";
      }
    }

    // Déterminer le type de chip (Apple Silicon vs Intel)
    let chipType = "Intel";
    try {
      const { stdout: archOut } = await execAsync("uname -m");
      if (archOut.trim() === "arm64") {
        chipType = "Apple Silicon";
      }
    } catch {
      // Ignorer si uname échoue
    }

    // Récupérer le modèle de Mac
    let macModel = "";
    try {
      const { stdout: modelOut } = await execAsync(
        "system_profiler SPHardwareDataType | grep 'Model Name' | cut -d: -f2"
      );
      macModel = modelOut.trim();
    } catch {
      // Ignorer
    }

    // Déterminer la version majeure (14 = Sonoma, 15 = Sequoia)
    const majorVersion = productVersion.split(".")[0] || "";

    return {
      ...base,
      osName: `${productName} ${productVersion}`,
      osVersion: majorVersion,
      buildNumber: buildVersion,
      chipType,
      macModel,
      manufacturer: "Apple",
      model: macModel,
    };
  } catch (error) {
    console.error("Erreur détection macOS:", error);
    return base;
  }
}

// Détection Linux via /etc/os-release
async function detectLinuxSystem(): Promise<DetectedSystem> {
  const base: DetectedSystem = {
    osFamily: "Linux",
    detectedAt: new Date().toISOString(),
  };

  try {
    // Lire /etc/os-release
    let distro = "";
    let distroVersion = "";
    let prettyName = "";
    
    if (fs.existsSync("/etc/os-release")) {
      const osRelease = fs.readFileSync("/etc/os-release", "utf8");
      const lines = osRelease.split("\n");
      
      for (const line of lines) {
        if (line.startsWith("ID=")) {
          distro = line.split("=")[1]?.replace(/"/g, "").trim() || "";
        } else if (line.startsWith("VERSION_ID=")) {
          distroVersion = line.split("=")[1]?.replace(/"/g, "").trim() || "";
        } else if (line.startsWith("PRETTY_NAME=")) {
          prettyName = line.split("=")[1]?.replace(/"/g, "").trim() || "";
        }
      }
    }

    // Récupérer la version du kernel
    let kernelVersion = "";
    try {
      const { stdout } = await execAsync("uname -r");
      kernelVersion = stdout.trim();
    } catch {
      // Ignorer
    }

    // Détecter l'environnement de bureau
    let desktopEnvironment = process.env.XDG_CURRENT_DESKTOP || process.env.DESKTOP_SESSION || "";

    // Récupérer les infos hardware
    let manufacturer = "";
    let model = "";
    try {
      if (fs.existsSync("/sys/class/dmi/id/sys_vendor")) {
        manufacturer = fs.readFileSync("/sys/class/dmi/id/sys_vendor", "utf8").trim();
      }
      if (fs.existsSync("/sys/class/dmi/id/product_name")) {
        model = fs.readFileSync("/sys/class/dmi/id/product_name", "utf8").trim();
      }
    } catch {
      // Ignorer
    }

    // Normaliser le nom de la distribution
    const normalizedDistro = distro.charAt(0).toUpperCase() + distro.slice(1);

    return {
      ...base,
      osName: prettyName || `${normalizedDistro} ${distroVersion}`,
      osVersion: distroVersion,
      distro: normalizedDistro,
      distroVersion,
      kernelVersion,
      desktopEnvironment,
      manufacturer,
      model,
    };
  } catch (error) {
    console.error("Erreur détection Linux:", error);
    return base;
  }
}

// Détection du système (dispatch selon l'OS)
async function detectSystem(): Promise<DetectedSystem> {
  const osFamily = detectOSFamily();
  
  switch (osFamily) {
    case "Windows":
      return detectWindowsSystem();
    case "macOS":
      return detectMacOSSystem();
    case "Linux":
      return detectLinuxSystem();
    default:
      return {
        osFamily: "Unknown",
        detectedAt: new Date().toISOString(),
      };
  }
}

// ============================================================================
// BASELINES DISPONIBLES
// ============================================================================

// Baselines Windows
const WINDOWS_BASELINES = [
  { filename: "msft_windows_11_24h2_machine.json", os: "11", minBuild: 26100, maxBuild: 99999 },
  { filename: "msft_windows_11_22h2_machine.json", os: "11", minBuild: 22000, maxBuild: 26099 },
  { filename: "msft_windows_10_22h2_machine.json", os: "10", minBuild: 10000, maxBuild: 21999 },
];

// Baselines macOS
const MACOS_BASELINES = [
  { filename: "cis_macos_sequoia_machine.json", minVersion: 15, maxVersion: 15.99 },
  { filename: "cis_macos_sonoma_machine.json", minVersion: 14, maxVersion: 14.99 },
];

// Baselines Linux
const LINUX_BASELINES = [
  { filename: "cis_ubuntu_2404_machine.json", distro: "Ubuntu", minVersion: "24.04", maxVersion: "24.99" },
  { filename: "cis_ubuntu_2404_machine.json", distro: "Ubuntu", minVersion: "22.04", maxVersion: "23.99" },
  { filename: "cis_debian_12_machine.json", distro: "Debian", minVersion: "12", maxVersion: "12.99" },
  { filename: "cis_fedora_40_machine.json", distro: "Fedora", minVersion: "39", maxVersion: "41" },
];

// ============================================================================
// SÉLECTION DU BASELINE
// ============================================================================

// Sélection du baseline Windows
function pickWindowsBaseline(system: DetectedSystem): { filename: string; folder: string } {
  const build = parseInt(system.buildNumber || "0");
  const osVersion = system.osVersion || "";
  
  // 1. Chercher un baseline exact pour le build
  for (const baseline of WINDOWS_BASELINES) {
    if (build >= baseline.minBuild && build <= baseline.maxBuild) {
      return { filename: baseline.filename, folder: "windows" };
    }
  }

  // 2. Fallback par version d'OS
  if (osVersion === "11" || build >= 22000) {
    if (build >= 26100) {
      return { filename: "msft_windows_11_24h2_machine.json", folder: "windows" };
    }
    return { filename: "msft_windows_11_22h2_machine.json", folder: "windows" };
  }

  // 3. Fallback Windows 10
  return { filename: "msft_windows_10_22h2_machine.json", folder: "windows" };
}

// Sélection du baseline macOS
function pickMacOSBaseline(system: DetectedSystem): { filename: string; folder: string } {
  const version = parseFloat(system.osVersion || "0");
  
  for (const baseline of MACOS_BASELINES) {
    if (version >= baseline.minVersion && version <= baseline.maxVersion) {
      return { filename: baseline.filename, folder: "macos" };
    }
  }
  
  // Fallback vers la dernière version
  return { filename: "cis_macos_sequoia_machine.json", folder: "macos" };
}

// Sélection du baseline Linux
function pickLinuxBaseline(system: DetectedSystem): { filename: string; folder: string } {
  const distro = system.distro || "";
  const version = system.distroVersion || "";
  
  // Chercher un baseline pour la distro spécifique
  for (const baseline of LINUX_BASELINES) {
    if (baseline.distro.toLowerCase() === distro.toLowerCase()) {
      const versionNum = parseFloat(version);
      const minVer = parseFloat(baseline.minVersion);
      const maxVer = parseFloat(baseline.maxVersion);
      
      if (versionNum >= minVer && versionNum <= maxVer) {
        return { filename: baseline.filename, folder: "linux" };
      }
    }
  }
  
  // Fallbacks par famille de distro
  const distroLower = distro.toLowerCase();
  
  // Famille Debian/Ubuntu
  if (["ubuntu", "linuxmint", "pop", "elementary", "zorin"].includes(distroLower)) {
    return { filename: "cis_ubuntu_2404_machine.json", folder: "linux" };
  }
  
  // Famille Debian
  if (["debian", "kali", "parrot", "mx"].includes(distroLower)) {
    return { filename: "cis_debian_12_machine.json", folder: "linux" };
  }
  
  // Famille Red Hat/Fedora
  if (["fedora", "rhel", "centos", "rocky", "alma", "oracle"].includes(distroLower)) {
    return { filename: "cis_fedora_40_machine.json", folder: "linux" };
  }
  
  // Fallback générique vers Ubuntu (le plus commun)
  return { filename: "cis_ubuntu_2404_machine.json", folder: "linux" };
}

// Sélection du baseline selon l'OS
function pickBaseline(system: DetectedSystem): { filename: string; folder: string } {
  switch (system.osFamily) {
    case "Windows":
      return pickWindowsBaseline(system);
    case "macOS":
      return pickMacOSBaseline(system);
    case "Linux":
      return pickLinuxBaseline(system);
    default:
      return { filename: "", folder: "" };
  }
}

// ============================================================================
// CHARGEMENT DES BASELINES
// ============================================================================

// Charger un baseline
function loadBaseline(filename: string, folder: string): Finding[] {
  const baselinesDir = path.join(process.cwd(), "data", "baselines", folder);
  const filePath = path.join(baselinesDir, filename);

  if (!fs.existsSync(filePath)) {
    console.warn("Baseline non trouvé:", filePath);
    return [];
  }

  try {
    const content = fs.readFileSync(filePath, "utf8");
    const data = JSON.parse(content);

    if (Array.isArray(data)) {
      return data;
    } else if (data.findings && Array.isArray(data.findings)) {
      return data.findings;
    }

    return [];
  } catch (error) {
    console.error("Erreur chargement baseline:", error);
    return [];
  }
}

// Charger les données complètes du baseline (avec métadonnées et variantes)
function loadBaselineData(filename: string, folder: string): any {
  const baselinesDir = path.join(process.cwd(), "data", "baselines", folder);
  const filePath = path.join(baselinesDir, filename);

  if (!fs.existsSync(filePath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(filePath, "utf8");
    return JSON.parse(content);
  } catch (error) {
    console.error("Erreur chargement baseline data:", error);
    return null;
  }
}

// ============================================================================
// VÉRIFICATION DES FINDINGS
// ============================================================================

// Vérifier une valeur de registre (Windows)
async function checkRegistryValue(regPath: string, regItem: string): Promise<string | null> {
  try {
    const pathForReg = regPath
      .replace("HKLM:\\", "HKLM\\")
      .replace("HKCU:\\", "HKCU\\");

    const { stdout } = await execAsync(
      `reg query "${pathForReg}" /v "${regItem}" 2>nul`,
      { windowsHide: true }
    );

    const lines = stdout.split("\n");
    for (const line of lines) {
      if (line.includes(regItem)) {
        const parts = line.trim().split(/\s{2,}/);
        if (parts.length >= 3) {
          return parts[2];
        }
      }
    }

    return null;
  } catch {
    return null;
  }
}

// Vérifier une valeur via defaults (macOS)
async function checkDefaultsValue(domain: string, key: string): Promise<string | null> {
  try {
    const { stdout } = await execAsync(`defaults read ${domain} ${key} 2>/dev/null`);
    return stdout.trim();
  } catch {
    return null;
  }
}

// Vérifier via une commande shell (macOS/Linux)
async function checkCommandValue(command: string): Promise<string | null> {
  try {
    const { stdout } = await execAsync(command, { timeout: 5000 });
    return stdout.trim();
  } catch {
    return null;
  }
}

// Vérifier une valeur sysctl (Linux)
async function checkSysctlValue(key: string): Promise<string | null> {
  try {
    const { stdout } = await execAsync(`sysctl -n ${key} 2>/dev/null`);
    return stdout.trim();
  } catch {
    return null;
  }
}

// Vérifier les politiques de compte Windows (net accounts)
async function checkAccountPolicy(policyName: string): Promise<string | null> {
  try {
    const { stdout } = await execAsync("net accounts", { windowsHide: true });
    // Nettoyer la sortie - remplacer les retours chariot et espaces multiples
    const cleanedOutput = stdout
      .replace(/\r/g, "")
      .replace(/\n\s+/g, " ")
      .replace(/\s+/g, " ");
    
    // Mapper les noms de politiques aux patterns regex pour trouver les valeurs
    // Utiliser des patterns qui marchent avec ou sans accents
    const policyPatterns: Record<string, RegExp> = {
      // Account lockout duration - "Durée du verrouillage (min):" en français
      "account lockout duration": /verrouillage\s*\(min\)[^:]*:\s*(\d+)/i,
      // Account lockout threshold - "Seuil de verrouillage:" en français
      "account lockout threshold": /Seuil de verrouillage[^:]*:\s*(\d+)/i,
      // Reset account lockout counter - "Fenêtre d'observation du verrouillage (min):" en français
      "reset account lockout counter": /observation[^:]*verrouillage[^:]*:\s*(\d+)/i,
      // Password history - "Nombre de mots de passe antérieurs à conserver:" en français
      "length of password history maintained": /passe ant[^\s]*rieurs[^:]*:\s*(\d+|Aucune|None)/i,
      // Minimum password length - "Longueur minimale du mot de passe:" en français
      "minimum password length": /Longueur minimale[^:]*:\s*(\d+)/i,
      // Maximum password age - "Durée de vie maximale du mot de passe (jours):" en français
      "maximum password age": /vie maximale[^:]*:\s*(\d+)/i,
      // Minimum password age - "Durée de vie minimale du mot de passe (jours):" en français
      "minimum password age": /vie minimale[^:]*:\s*(\d+)/i,
    };
    
    const pattern = policyPatterns[policyName.toLowerCase()];
    if (!pattern) {
      return null;
    }
    
    const match = cleanedOutput.match(pattern);
    if (match) {
      const value = match[1];
      // Normaliser les valeurs "jamais"/"aucune" en "0" pour la comparaison
      if (value.toLowerCase() === "jamais" || value.toLowerCase() === "never" || value.toLowerCase() === "aucune" || value.toLowerCase() === "none") {
        return "0";
      }
      return value;
    }
    
    return null;
  } catch {
    return null;
  }
}

// Vérifier les paramètres secedit (exportation temporaire de la policy)
async function checkSeceditValue(settingPath: string): Promise<string | null> {
  try {
    // Exporter la configuration de sécurité dans un fichier temporaire
    const tempFile = path.join(os.tmpdir(), `secedit_${Date.now()}.inf`);
    
    await execAsync(`secedit /export /cfg "${tempFile}" /quiet`, { 
      windowsHide: true,
      timeout: 10000 
    });
    
    // Lire le fichier exporté
    if (fs.existsSync(tempFile)) {
      const content = fs.readFileSync(tempFile, "utf16le");
      fs.unlinkSync(tempFile); // Nettoyer
      
      // Chercher le paramètre (format: SettingName = Value)
      const settingName = settingPath.split("\\").pop() || settingPath;
      const regex = new RegExp(`${settingName}\\s*=\\s*(.+)`, "i");
      const match = content.match(regex);
      
      if (match) {
        return match[1].trim();
      }
    }
    
    return null;
  } catch {
    return null;
  }
}

// Vérifier les règles ASR (Attack Surface Reduction) de Windows Defender
async function checkAsrRule(ruleGuid: string): Promise<string | null> {
  try {
    const psCommand = `(Get-MpPreference).AttackSurfaceReductionRules_Ids | ForEach-Object { $i = [array]::IndexOf((Get-MpPreference).AttackSurfaceReductionRules_Ids, $_); if ($_ -eq '${ruleGuid}') { (Get-MpPreference).AttackSurfaceReductionRules_Actions[$i] } }`;
    
    const { stdout } = await execAsync(`powershell -NoProfile -Command "${psCommand}"`, {
      windowsHide: true,
      timeout: 10000
    });
    
    const value = stdout.trim();
    // 0 = Disabled, 1 = Block, 2 = Audit, 6 = Warn
    return value || "0";
  } catch {
    return null;
  }
}

// Vérifier l'état d'un service Windows
async function checkWindowsService(serviceName: string): Promise<{ status: string; startType: string } | null> {
  try {
    const psCommand = `$svc = Get-Service -Name '${serviceName}' -ErrorAction SilentlyContinue; if ($svc) { $startType = (Get-WmiObject Win32_Service -Filter "Name='${serviceName}'" -ErrorAction SilentlyContinue).StartMode; @{Status=$svc.Status.ToString();StartType=$startType} | ConvertTo-Json -Compress }`;
    
    const { stdout } = await execAsync(`powershell -NoProfile -Command "${psCommand}"`, {
      windowsHide: true,
      timeout: 10000
    });
    
    if (stdout.trim()) {
      const result = JSON.parse(stdout.trim());
      return {
        status: result.Status || "Unknown",
        startType: result.StartType || "Unknown"
      };
    }
    return null;
  } catch {
    return null;
  }
}

// Vérifier un finding Windows
async function checkWindowsFinding(finding: Finding, system?: DetectedSystem): Promise<Finding> {
  const result: Finding = { ...finding, status: "unknown", currentValue: undefined };

  // Si le finding a déjà une valeur de compatibilité définie, le retourner tel quel
  if (finding.currentValue?.includes("Non disponible") || finding.currentValue?.includes("non compatible")) {
    return finding;
  }

  // Fonction pour normaliser les valeurs (convertir 0x1 en 1, etc.)
  const normalizeValue = (val: string): string => {
    const trimmed = val.trim().toLowerCase();
    // Convertir les valeurs hexadécimales (0x1, 0x0, etc.) en décimal
    if (trimmed.startsWith("0x")) {
      return String(parseInt(trimmed, 16));
    }
    return trimmed;
  };

  // Méthode Registry
  if (finding.method === "Registry" && finding.registryPath && finding.registryItem) {
    const currentValue = await checkRegistryValue(finding.registryPath, finding.registryItem);
    
    if (currentValue !== null) {
      // La clé existe, on utilise sa valeur
      const normalizedCurrent = normalizeValue(currentValue);
      result.currentValue = normalizedCurrent;

      if (finding.recommendedValue !== undefined) {
        const recommended = normalizeValue(String(finding.recommendedValue));
        const operator = finding.operator || "=";

        if (operator === "=") {
          result.status = normalizedCurrent === recommended ? "pass" : "fail";
        } else if (operator === ">=") {
          result.status = parseInt(normalizedCurrent) >= parseInt(recommended) ? "pass" : "fail";
        } else if (operator === "<=") {
          result.status = parseInt(normalizedCurrent) <= parseInt(recommended) ? "pass" : "fail";
        }
      }
    } else {
      // La clé n'existe pas - Windows utilise la valeur par défaut
      // Cela signifie que le paramètre n'a jamais été configuré (pas de GPO, pas de modification manuelle)
      if (finding.defaultValue !== undefined && finding.defaultValue !== "") {
        const defaultVal = normalizeValue(String(finding.defaultValue));
        result.currentValue = `${defaultVal} (non configuré)`;
        
        if (finding.recommendedValue !== undefined) {
          const recommended = normalizeValue(String(finding.recommendedValue));
          const operator = finding.operator || "=";

          if (operator === "=") {
            result.status = defaultVal === recommended ? "pass" : "fail";
          } else if (operator === ">=") {
            result.status = parseInt(defaultVal) >= parseInt(recommended) ? "pass" : "fail";
          } else if (operator === "<=") {
            result.status = parseInt(defaultVal) <= parseInt(recommended) ? "pass" : "fail";
          }
        }
      } else {
        // Pas de valeur par défaut connue - considérer comme non conforme
        // car le paramètre de sécurité recommandé n'est pas configuré
        result.currentValue = "Non configuré";
        result.status = "fail";
      }
    }
  }
  // Méthode accountpolicy (net accounts)
  else if (finding.method === "accountpolicy") {
    const currentValue = await checkAccountPolicy(finding.name || "");
    
    if (currentValue !== null) {
      result.currentValue = currentValue;
      
      if (finding.recommendedValue !== undefined) {
        const operator = finding.operator || "=";
        const current = parseInt(currentValue) || 0;
        const recommended = parseInt(finding.recommendedValue) || 0;

        if (operator === "=") {
          result.status = current === recommended ? "pass" : "fail";
        } else if (operator === ">=") {
          result.status = current >= recommended ? "pass" : "fail";
        } else if (operator === "<=") {
          result.status = current <= recommended ? "pass" : "fail";
        }
      }
    } else if (finding.defaultValue !== undefined) {
      // net accounts n'a pas retourné la valeur - utiliser la valeur Windows par défaut
      result.currentValue = `${finding.defaultValue} (valeur Windows)`;
      
      if (finding.recommendedValue !== undefined) {
        const operator = finding.operator || "=";
        const defaultNum = parseInt(finding.defaultValue) || 0;
        const recommended = parseInt(finding.recommendedValue) || 0;

        if (operator === "=") {
          result.status = defaultNum === recommended ? "pass" : "fail";
        } else if (operator === ">=") {
          result.status = defaultNum >= recommended ? "pass" : "fail";
        } else if (operator === "<=") {
          result.status = defaultNum <= recommended ? "pass" : "fail";
        }
      }
    } else {
      // Impossible de lire - considérer comme non conforme
      result.currentValue = "Non disponible";
      result.status = "fail";
    }
  }
  // Méthode secedit (paramètres de sécurité locaux - nécessite des droits admin)
  else if (finding.method === "secedit" && finding.methodArgument) {
    const currentValue = await checkSeceditValue(finding.methodArgument);
    
    if (currentValue !== null) {
      result.currentValue = currentValue;
      if (finding.recommendedValue !== undefined) {
        const operator = finding.operator || "=";
        if (operator === "=") {
          result.status = currentValue === finding.recommendedValue ? "pass" : "fail";
        } else if (operator === ">=") {
          result.status = parseInt(currentValue) >= parseInt(finding.recommendedValue) ? "pass" : "fail";
        }
      }
    } else if (finding.defaultValue !== undefined) {
      // secedit a échoué mais on a une valeur par défaut
      result.currentValue = `${finding.defaultValue} (par défaut Windows)`;
      if (finding.recommendedValue !== undefined) {
        const operator = finding.operator || "=";
        if (operator === "=") {
          result.status = String(finding.defaultValue) === String(finding.recommendedValue) ? "pass" : "fail";
        } else if (operator === ">=") {
          result.status = parseInt(finding.defaultValue) >= parseInt(finding.recommendedValue) ? "pass" : "fail";
        }
      }
    } else {
      result.currentValue = "Droits admin requis";
      result.status = "unknown";
      result.skipReason = "admin_required";
    }
  }
  // Méthode MpPreferenceAsr (règles ASR Windows Defender)
  else if (finding.method === "MpPreferenceAsr" && finding.methodArgument) {
    const currentValue = await checkAsrRule(finding.methodArgument);
    
    if (currentValue !== null && currentValue !== "") {
      result.currentValue = currentValue === "1" ? "Activé (Block)" : currentValue === "2" ? "Audit" : currentValue === "0" ? "Désactivé" : currentValue;
      if (finding.recommendedValue !== undefined) {
        result.status = currentValue === finding.recommendedValue ? "pass" : "fail";
      }
    } else {
      // ASR non configuré (règle non présente = désactivée par défaut)
      result.currentValue = "Non configuré (désactivé)";
      // Par défaut les règles ASR sont désactivées, donc si on recommande "1" (activé), c'est un fail
      if (finding.recommendedValue !== undefined) {
        result.status = finding.recommendedValue === "0" ? "pass" : "fail";
      }
    }
  }
  // Méthode service (vérifier l'état d'un service Windows)
  else if (finding.method === "service" && finding.methodArgument) {
    const serviceName = finding.methodArgument;
    const serviceInfo = await checkWindowsService(serviceName);
    
    if (serviceInfo !== null) {
      // Le service existe
      result.currentValue = `${serviceInfo.status} (${serviceInfo.startType})`;
      
      // Vérifier selon ce qu'on attend
      if (finding.recommendedValue !== undefined) {
        const recommended = String(finding.recommendedValue).toLowerCase();
        const currentStatus = serviceInfo.status.toLowerCase();
        const currentStartType = serviceInfo.startType.toLowerCase();
        
        // Si on recommande "Disabled" ou "4", le service doit être désactivé
        if (recommended === "disabled" || recommended === "4") {
          result.status = (currentStartType === "disabled" || currentStartType === "manual") ? "pass" : "fail";
        }
        // Si on recommande "Running" ou "Automatic", le service doit tourner
        else if (recommended === "running" || recommended === "automatic" || recommended === "2") {
          result.status = (currentStatus === "running" && currentStartType === "auto") ? "pass" : "fail";
        }
        // Sinon comparaison directe du status
        else {
          result.status = currentStatus === recommended ? "pass" : "fail";
        }
      } else {
        // Pas de valeur recommandée = on vérifie juste que le service existe
        result.status = "pass";
      }
    } else {
      // Le service n'existe pas
      result.currentValue = "Service non installé";
      // Si on recommandait de le désactiver, c'est un pass (il n'existe même pas)
      if (finding.recommendedValue !== undefined) {
        const recommended = String(finding.recommendedValue).toLowerCase();
        if (recommended === "disabled" || recommended === "4") {
          result.status = "pass";
        } else {
          result.status = "fail";
        }
      } else {
        result.status = "unknown";
        result.skipReason = "service_not_installed";
      }
    }
  }
  // Méthode manual (vérification manuelle requise)
  else if (finding.method === "manual") {
    result.currentValue = "Vérification manuelle requise";
    result.status = "unknown";
    result.skipReason = "manual_check";
  }

  return result;
}

// Vérifier un finding macOS
async function checkMacOSFinding(finding: Finding): Promise<Finding> {
  const result: Finding = { ...finding, status: "unknown", currentValue: undefined };

  if (finding.method === "defaults" && finding.domain && finding.key) {
    const currentValue = await checkDefaultsValue(finding.domain, finding.key);
    result.currentValue = currentValue || "Non défini";

    if (currentValue !== null && finding.recommendedValue !== undefined) {
      const operator = finding.operator || "=";
      if (operator === "=") {
        result.status = currentValue === finding.recommendedValue ? "pass" : "fail";
      } else if (operator === "contains") {
        result.status = currentValue.includes(finding.recommendedValue) ? "pass" : "fail";
      }
    }
  } else if (finding.method === "command" && finding.command) {
    const currentValue = await checkCommandValue(finding.command);
    result.currentValue = currentValue || "Non défini";

    if (currentValue !== null && finding.recommendedValue !== undefined) {
      const operator = finding.operator || "contains";
      if (operator === "contains") {
        result.status = currentValue.toLowerCase().includes(finding.recommendedValue.toLowerCase()) ? "pass" : "fail";
      } else if (operator === "=") {
        result.status = currentValue === finding.recommendedValue ? "pass" : "fail";
      }
    }
  } else if (finding.method === "info") {
    // Les findings "info" sont juste informatifs
    result.status = "unknown";
  }

  return result;
}

// Vérifier un finding Linux
async function checkLinuxFinding(finding: Finding): Promise<Finding> {
  const result: Finding = { ...finding, status: "unknown", currentValue: undefined };

  if (finding.method === "sysctl" && finding.key) {
    const currentValue = await checkSysctlValue(finding.key);
    result.currentValue = currentValue || "Non défini";

    if (currentValue !== null && finding.recommendedValue !== undefined) {
      const operator = finding.operator || "=";
      if (operator === "=") {
        result.status = currentValue === finding.recommendedValue ? "pass" : "fail";
      } else if (operator === ">=") {
        result.status = parseInt(currentValue) >= parseInt(finding.recommendedValue) ? "pass" : "fail";
      } else if (operator === "<=") {
        result.status = parseInt(currentValue) <= parseInt(finding.recommendedValue) ? "pass" : "fail";
      }
    }
  } else if (finding.method === "command" && finding.command) {
    const currentValue = await checkCommandValue(finding.command);
    result.currentValue = currentValue || "Non défini";

    if (currentValue !== null && finding.recommendedValue !== undefined) {
      const operator = finding.operator || "=";
      if (operator === "=") {
        result.status = currentValue === finding.recommendedValue ? "pass" : "fail";
      } else if (operator === ">=") {
        result.status = parseInt(currentValue) >= parseInt(finding.recommendedValue) ? "pass" : "fail";
      } else if (operator === "contains") {
        result.status = currentValue.toLowerCase().includes(finding.recommendedValue.toLowerCase()) ? "pass" : "fail";
      }
    }
  } else if (finding.method === "file" && finding.path) {
    try {
      if (fs.existsSync(finding.path)) {
        result.currentValue = "exists";
        if (finding.pattern) {
          const content = fs.readFileSync(finding.path, "utf8");
          result.status = content.includes(finding.pattern) ? "pass" : "fail";
        } else {
          result.status = "pass";
        }
      } else {
        result.currentValue = "not found";
        result.status = "fail";
      }
    } catch {
      result.currentValue = "error reading";
      result.status = "unknown";
    }
  }

  return result;
}

// Vérifier un finding selon l'OS
async function checkFinding(finding: Finding, osFamily: string, system?: DetectedSystem): Promise<Finding> {
  switch (osFamily) {
    case "Windows":
      return checkWindowsFinding(finding, system);
    case "macOS":
      return checkMacOSFinding(finding);
    case "Linux":
      return checkLinuxFinding(finding);
    default:
      return { ...finding, status: "unknown" };
  }
}

// ============================================================================
// APPLICATION DES VARIANTES ET FILTRAGE
// ============================================================================

// IDs des findings qui nécessitent des fonctionnalités spécifiques
const REQUIRES_CET = ["10698"]; // Kernel-mode Hardware-enforced Stack Protection
const REQUIRES_VBS = ["10672", "10673", "10674"]; // VBS, HVCI, Credential Guard
const REQUIRES_PRO_OR_ENTERPRISE = ["10672", "10673", "10674", "10700"]; // VBS, HVCI, Credential Guard, LSASS PPL via policy

// Appliquer les variantes du baseline selon le système détecté
function applyVariants(findings: Finding[], system: DetectedSystem, baselineData: any): Finding[] {
  let result = [...findings];

  // === WINDOWS ===
  if (system.osFamily === "Windows") {
    // 1. Supprimer les findings non supportés par l'édition (depuis le baseline)
    if (baselineData?.variants && system.osEdition) {
      const variants = baselineData.variants;
      if (variants[system.osEdition]?.excludeFindings) {
        const excludeIds = variants[system.osEdition].excludeFindings;
        result = result.filter((f) => !excludeIds.includes(f.id));
      }
    }
    
    // 2. Supprimer les findings Pro/Enterprise sur Windows Home
    if (system.osEdition === "Home") {
      result = result.filter(f => !REQUIRES_PRO_OR_ENTERPRISE.includes(f.id));
    }
    
    // 3. Supprimer les findings CET si le processeur ne le supporte pas
    if (system.processorFeatures && !system.processorFeatures.supportsCET) {
      result = result.filter(f => !REQUIRES_CET.includes(f.id));
    }
    
    // 4. Supprimer les findings VBS si le processeur ne le supporte pas
    if (system.processorFeatures && !system.processorFeatures.supportsVBS) {
      result = result.filter(f => !REQUIRES_VBS.includes(f.id));
    }

    // 5. Ajouter les findings spécifiques au fabricant
    if (baselineData?.variants && system.manufacturer) {
      const variants = baselineData.variants;
      const mfr = Object.keys(variants).find((key) =>
        system.manufacturer!.toLowerCase().includes(key.toLowerCase())
      );
      if (mfr && variants[mfr]?.additionalFindings) {
        result.push(...variants[mfr].additionalFindings);
      }
    }

    // 6. Ajouter les findings Enterprise
    if (baselineData?.variants && system.osEdition === "Enterprise" && baselineData.variants.Enterprise?.additionalFindings) {
      result.push(...baselineData.variants.Enterprise.additionalFindings);
    }
  }

  // === macOS ===
  if (system.osFamily === "macOS" && baselineData?.variants) {
    const variants = baselineData.variants;
    // Ajouter les findings spécifiques Apple Silicon vs Intel
    if (system.chipType && variants[system.chipType]?.additionalFindings) {
      result.push(...variants[system.chipType].additionalFindings);
    }
  }

  // === Linux ===
  if (system.osFamily === "Linux" && baselineData?.variants) {
    const variants = baselineData.variants;
    // Ajouter les findings selon le type (Server vs Desktop)
    const hasDesktop = !!system.desktopEnvironment;
    const variantKey = hasDesktop ? "Desktop" : "Server";
    
    if (variants[variantKey]?.additionalFindings) {
      result.push(...variants[variantKey].additionalFindings);
    }
    
    // Exclure les findings non pertinents
    if (variants[variantKey]?.excludeFindings) {
      const excludeIds = variants[variantKey].excludeFindings;
      result = result.filter((f) => !excludeIds.includes(f.id));
    }
  }

  return result;
}

// ============================================================================
// ROUTE API PRINCIPALE
// ============================================================================

export async function GET() {
  try {
    // 1. Détecter le système d'exploitation
    const system = await detectSystem();

    // 2. Sélectionner le baseline approprié
    const { filename: baselineFilename, folder: baselineFolder } = pickBaseline(system);
    
    if (!baselineFilename || !baselineFolder) {
      return NextResponse.json({
        system,
        baseline: null,
        findings: [],
        error: "Système d'exploitation non supporté",
        scannedAt: new Date().toISOString(),
      });
    }

    // 3. Charger le baseline
    const baselineData = loadBaselineData(baselineFilename, baselineFolder);
    let findings: Finding[] = baselineData?.findings || [];

    // 4. Appliquer les variantes selon le système
    findings = applyVariants(findings, system, baselineData);

    // 5. Vérifier chaque finding (limité pour les performances)
    const checkedFindings: Finding[] = [];
    const maxFindings = 50; // Limiter le nombre de vérifications
    const findingsToCheck = findings.slice(0, maxFindings);

    for (const finding of findingsToCheck) {
      // Si le finding a déjà été marqué comme incompatible, ne pas le revérifier
      if (finding.status === "unknown" && finding.currentValue?.includes("Non disponible")) {
        checkedFindings.push(finding);
      } else {
        const checked = await checkFinding(finding, system.osFamily, system);
        checkedFindings.push(checked);
      }
    }

    // 6. Filtrer les findings non pertinents (services non installés, checks manuels)
    const filteredFindings = checkedFindings.filter(f => {
      // Supprimer les services non installés qui restent en "unknown"
      if (f.status === "unknown" && f.skipReason === "service_not_installed") {
        return false;
      }
      // Supprimer les vérifications manuelles
      if (f.status === "unknown" && f.skipReason === "manual_check") {
        return false;
      }
      return true;
    });

    // 7. Retourner les résultats
    return NextResponse.json({
      system,
      baseline: baselineFilename,
      baselineFolder,
      findings: filteredFindings,
      totalFindings: findings.length,
      scannedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error("Erreur analyse:", error);
    return NextResponse.json(
      { error: error.message || "Erreur lors de l'analyse" },
      { status: 500 }
    );
  }
}

// Supporter aussi POST pour la page findings - avec support des infos système passées
export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => ({}));
    
    // Si des infos système sont passées, les utiliser pour enrichir la détection
    // Sinon, faire une détection complète
    let system: DetectedSystem;
    
    if (body.system && (body.system.osFamily || body.system.osName)) {
      // Utiliser les infos passées mais re-détecter certains éléments si nécessaire
      const detectedSystem = await detectSystem();
      
      // Normaliser osFamily - detect-system renvoie "Windows 11" mais on veut "Windows"
      let normalizedOsFamily = body.system.osFamily || detectedSystem.osFamily;
      if (normalizedOsFamily.includes("Windows")) {
        normalizedOsFamily = "Windows";
      } else if (normalizedOsFamily.includes("mac") || normalizedOsFamily.includes("Mac")) {
        normalizedOsFamily = "macOS";
      } else if (normalizedOsFamily.includes("Linux") || normalizedOsFamily.includes("linux")) {
        normalizedOsFamily = "Linux";
      }
      
      system = {
        ...detectedSystem,
        // Fusionner avec les infos passées (elles peuvent être plus complètes côté client)
        osFamily: normalizedOsFamily as "Windows" | "Linux" | "macOS" | "Unknown",
        osName: body.system.osName || detectedSystem.osName,
        osVersion: body.system.osVersion || detectedSystem.osVersion,
        osEdition: body.system.osEdition || detectedSystem.osEdition,
        buildNumber: body.system.buildNumber || detectedSystem.buildNumber,
        manufacturer: body.system.manufacturer || detectedSystem.manufacturer,
        model: body.system.model || detectedSystem.model,
        processor: body.system.processor || detectedSystem.processor,
      };
      
      // Conserver les capabilities si fournies
      if (body.system.capabilities) {
        system.processorFeatures = {
          supportsCET: body.system.capabilities.supportsCET,
          supportsVBS: body.system.capabilities.supportsVBS,
        };
      }
    } else {
      system = await detectSystem();
    }

    // 2. Sélectionner le baseline approprié
    const { filename: baselineFilename, folder: baselineFolder } = pickBaseline(system);
    
    if (!baselineFilename || !baselineFolder) {
      return NextResponse.json({
        system,
        baseline: null,
        findings: [],
        error: "Système d'exploitation non supporté",
        scannedAt: new Date().toISOString(),
      });
    }

    // 3. Charger le baseline
    const baselineData = loadBaselineData(baselineFilename, baselineFolder);
    let findings: Finding[] = baselineData?.findings || [];

    // 4. Appliquer les variantes selon le système
    findings = applyVariants(findings, system, baselineData);

    // 5. Vérifier chaque finding (limité pour les performances)
    const checkedFindings: Finding[] = [];
    const maxFindings = 50;
    const findingsToCheck = findings.slice(0, maxFindings);

    for (const finding of findingsToCheck) {
      if (finding.status === "unknown" && finding.currentValue?.includes("Non disponible")) {
        checkedFindings.push(finding);
      } else {
        const checked = await checkFinding(finding, system.osFamily, system);
        checkedFindings.push(checked);
      }
    }

    // 6. Filtrer les findings non pertinents
    const filteredFindings = checkedFindings.filter(f => {
      if (f.status === "unknown" && f.skipReason === "service_not_installed") {
        return false;
      }
      if (f.status === "unknown" && f.skipReason === "manual_check") {
        return false;
      }
      return true;
    });

    // 7. Retourner les résultats
    return NextResponse.json({
      system,
      baseline: baselineFilename,
      baselineFolder,
      findings: filteredFindings,
      totalFindings: findings.length,
      scannedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error("Erreur analyse POST:", error);
    return NextResponse.json(
      { error: error.message || "Erreur lors de l'analyse" },
      { status: 500 }
    );
  }
}