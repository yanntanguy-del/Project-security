// app/api/detect-system/route.ts
import { NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export async function GET() {
  try {
    // Détection rapide du système Windows
    const systemInfo = await detectWindowsSystem();
    return NextResponse.json(systemInfo);
  } catch (error) {
    console.error("Erreur lors de la détection du système:", error);
    return NextResponse.json(
      { error: "Impossible de détecter le système" },
      { status: 500 }
    );
  }
}

async function detectWindowsSystem() {
  // Récupérer les informations système via PowerShell
  const commands = {
    osInfo: `Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json`,
    computerInfo: `Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemType | ConvertTo-Json`,
    processor: `Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer | ConvertTo-Json -Compress`,
    // Détection des fonctionnalités de sécurité
    vbsStatus: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue | Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties, AvailableSecurityProperties | ConvertTo-Json -Compress`,
    hypervisor: `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent`
  };

  const results: any = {
    capabilities: {
      supportsVBS: false,
      supportsCET: false,
      vbsEnabled: false,
      hypervisorPresent: false,
      isHomeEdition: false
    }
  };

  // OS Info
  try {
    const { stdout } = await execAsync(`powershell -Command "${commands.osInfo}"`, { encoding: "utf8" });
    const osData = JSON.parse(stdout);
    results.osName = osData.Caption?.trim() || "Windows";
    results.osVersion = osData.Version || "";
    results.buildNumber = osData.BuildNumber || "";
    results.architecture = osData.OSArchitecture || "";
    
    // Déterminer l'édition
    const caption = osData.Caption?.toLowerCase() || "";
    if (caption.includes("home") || caption.includes("famille")) {
      results.osEdition = "Home";
      results.capabilities.isHomeEdition = true;
    } else if (caption.includes("pro")) {
      results.osEdition = "Pro";
    } else if (caption.includes("enterprise") || caption.includes("entreprise")) {
      results.osEdition = "Enterprise";
    } else if (caption.includes("education")) {
      results.osEdition = "Education";
    } else {
      results.osEdition = "Unknown";
    }

    // Déterminer la version Windows (10, 11, etc.)
    const buildNum = parseInt(osData.BuildNumber || "0");
    if (buildNum >= 22000) {
      results.osFamily = "Windows 11";
    } else if (buildNum >= 10240) {
      results.osFamily = "Windows 10";
    } else {
      results.osFamily = "Windows";
    }

  } catch (e) {
    console.error("Erreur OS Info:", e);
    results.osName = "Windows";
    results.osEdition = "Unknown";
  }

  // Computer Info
  try {
    const { stdout } = await execAsync(`powershell -Command "${commands.computerInfo}"`, { encoding: "utf8" });
    const computerData = JSON.parse(stdout);
    results.manufacturer = computerData.Manufacturer?.trim() || "";
    results.model = computerData.Model?.trim() || "";
    results.systemType = computerData.SystemType || "";
  } catch (e) {
    console.error("Erreur Computer Info:", e);
  }

  // Processor Info
  try {
    const { stdout } = await execAsync(`powershell -Command "${commands.processor}"`, { encoding: "utf8" });
    const cpuData = JSON.parse(stdout);
    // Peut être un tableau si plusieurs processeurs
    const cpu = Array.isArray(cpuData) ? cpuData[0] : cpuData;
    results.processor = cpu?.Name?.trim() || "";
    results.cpuManufacturer = cpu?.Manufacturer || "";
    
    // Détecter si le CPU supporte certaines fonctionnalités
    const cpuName = (cpu?.Name || "").toLowerCase();
    const cpuMfg = (cpu?.Manufacturer || "").toLowerCase();
    
    // Intel CET support (11th gen+)
    if (cpuMfg.includes("intel")) {
      const genMatch = cpuName.match(/(\d+)(?:th|st|nd|rd)?\s*gen/i) || cpuName.match(/i[3579]-(\d{2})/);
      if (genMatch) {
        const gen = parseInt(genMatch[1]);
        results.supportsCET = gen >= 11;
        results.capabilities.supportsCET = gen >= 11;
      }
    } else if (cpuMfg.includes("amd")) {
      // AMD Zen 3+ support
      const supportsCET = cpuName.includes("5") || cpuName.includes("7") || cpuName.includes("9");
      results.supportsCET = supportsCET;
      results.capabilities.supportsCET = supportsCET;
    }
  } catch (e) {
    console.error("Erreur Processor Info:", e);
  }

  // Détection VBS (Virtualization Based Security)
  try {
    const { stdout } = await execAsync(`powershell -Command "${commands.vbsStatus}"`, { encoding: "utf8", timeout: 5000 });
    if (stdout.trim()) {
      const vbsData = JSON.parse(stdout.trim());
      // VirtualizationBasedSecurityStatus: 0=Disabled, 1=Enabled but not running, 2=Running
      results.capabilities.vbsEnabled = vbsData.VirtualizationBasedSecurityStatus === 2;
      // Si VBS est disponible (même non activé), le CPU le supporte
      results.capabilities.supportsVBS = vbsData.AvailableSecurityProperties?.length > 0 || vbsData.VirtualizationBasedSecurityStatus > 0;
    }
  } catch (e) {
    // VBS non disponible ou erreur - probablement pas supporté
    results.capabilities.supportsVBS = false;
  }

  // Détection Hypervisor
  try {
    const { stdout } = await execAsync(`powershell -Command "${commands.hypervisor}"`, { encoding: "utf8", timeout: 3000 });
    results.capabilities.hypervisorPresent = stdout.trim().toLowerCase() === "true";
  } catch (e) {
    results.capabilities.hypervisorPresent = false;
  }

  // Liste des incompatibilités détectées pour affichage
  results.incompatibilities = [];
  
  if (results.capabilities.isHomeEdition) {
    results.incompatibilities.push({
      type: "edition",
      feature: "Fonctionnalités Pro/Enterprise",
      reason: "Windows Home ne supporte pas BitLocker, Credential Guard, VBS, et d'autres protections avancées"
    });
  }
  
  if (!results.capabilities.supportsCET) {
    results.incompatibilities.push({
      type: "cpu",
      feature: "Protection CET (Control-flow Enforcement)",
      reason: "Votre processeur ne supporte pas la technologie CET (nécessite Intel 11e gen+ ou AMD Zen 3+)"
    });
  }
  
  if (!results.capabilities.supportsVBS) {
    results.incompatibilities.push({
      type: "cpu_or_bios",
      feature: "Sécurité basée sur la virtualisation (VBS)",
      reason: "VBS n'est pas disponible. La virtualisation peut être désactivée dans le BIOS ou non supportée par le processeur"
    });
  }

  // Déterminer le baseline recommandé
  results.recommendedBaseline = determineBaseline(results);

  return results;
}

function determineBaseline(systemInfo: any): string {
  const osFamily = systemInfo.osFamily || "";
  const edition = systemInfo.osEdition || "";
  const buildNum = parseInt(systemInfo.buildNumber || "0");

  // Windows 11
  if (osFamily.includes("11")) {
    if (buildNum >= 26100) {
      return "msft_windows_11_24h2_machine";
    } else if (buildNum >= 22631) {
      return "msft_windows_11_23h2_machine";
    } else if (buildNum >= 22621) {
      return "msft_windows_11_22h2_machine";
    }
    return "msft_windows_11_24h2_machine"; // Default to latest
  }

  // Windows 10
  if (osFamily.includes("10")) {
    return "msft_windows_10_machine";
  }

  // Default
  return "msft_windows_11_24h2_machine";
}
