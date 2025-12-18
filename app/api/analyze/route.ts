import { NextResponse } from "next/server";
import os from "os";
import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export const runtime = "nodejs";

type BaselineFile = {
  metadata?: Record<string, any>;
  variants?: Record<
    string,
    {
      excludeFindings?: string[];
      additionalFindings?: any[];
      description?: string;
    }
  >;
  findings?: any[];
};

type ScanFinding = {
  id: string;
  name: string;
  category: string;
  method: string;
  severity: string;
  recommendedValue?: string;
  currentValue?: string;
  defaultValue?: string;
  operator?: string;
  description?: string;
  risk?: string;
  compatibility?: string;
  skipReason?: string;
  remediation?: any;
};

type ScanResult = {
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
  findings: Array<ScanFinding & { status: "pass" | "fail" | "unknown" }>;
};

function normalizeWindowsEdition(editionRaw: string): string {
  const ed = String(editionRaw || "").trim();
  const low = ed.toLowerCase();
  if (low.includes("home") || low === "core") return "Home";
  if (low.includes("pro")) return "Pro";
  if (low.includes("enterprise")) return "Enterprise";
  if (low.includes("education")) return "Education";
  return ed;
}

function parseOsRelease(contents: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of String(contents || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) continue;
    const k = trimmed.slice(0, idx).trim();
    let v = trimmed.slice(idx + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    out[k] = v;
  }
  return out;
}

function normalizeMacOsMajor(productVersion: string): string {
  const pv = String(productVersion || "").trim();
  const major = pv.split(".")[0];
  return major || pv;
}

async function execPowerShell(command: string, timeoutMs = 60000): Promise<string> {
  const ps = "powershell.exe";
  const args = [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    command,
  ];

  const { stdout } = await execFileAsync(ps, args, {
    encoding: "utf8",
    timeout: timeoutMs,
    windowsHide: true,
  });

  return String(stdout ?? "").trim();
}

async function execPosixShell(command: string, timeoutMs = 60000): Promise<string> {
  const shellPath = "/bin/bash";
  const { stdout } = await execFileAsync(shellPath, ["-lc", command], {
    encoding: "utf8",
    timeout: timeoutMs,
  });
  return String(stdout ?? "").trim();
}

async function detectSystemInfo() {
  const platform = os.platform();

  if (platform === "win32") {
    const osJson = await execPowerShell(
      "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json -Compress",
    );
    const edition = await execPowerShell(
      '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").EditionID',
    );
    const hwJson = await execPowerShell(
      "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model | ConvertTo-Json -Compress",
    );

    let osName = "Windows";
    let osVersion = "";
    let buildNumber = "";
    let manufacturer = "";
    let model = "";

    try {
      const o = JSON.parse(osJson);
      osName = String(o.Caption || "Windows");
      osVersion = String(o.Version || "");
      buildNumber = String(o.BuildNumber || "");
    } catch {
      // ignore
    }

    try {
      const h = JSON.parse(hwJson);
      manufacturer = String(h.Manufacturer || "");
      model = String(h.Model || "");
    } catch {
      // ignore
    }

    const build = parseInt(buildNumber || "0", 10);
    const osMajor = isNaN(build) ? "" : build >= 22000 ? "11" : "10";

    return {
      osFamily: "Windows",
      osName,
      osVersion: osMajor,
      osEdition: normalizeWindowsEdition(edition),
      buildNumber,
      manufacturer,
      model,
      platform,
    };
  }

  if (platform === "darwin") {
    const productName = await execPosixShell("sw_vers -productName 2>/dev/null || echo 'macOS'");
    const productVersion = await execPosixShell("sw_vers -productVersion 2>/dev/null || echo ''");
    const arch = os.arch();
    return {
      osFamily: "macOS",
      osName: productName || "macOS",
      osVersion: normalizeMacOsMajor(productVersion),
      osEdition: arch === "arm64" ? "Apple Silicon" : "Intel",
      buildNumber: String(productVersion || ""),
      manufacturer: "Apple",
      model: "",
      platform,
    };
  }

  if (platform === "linux") {
    let osName = "Linux";
    let osVersion = os.release();
    let osEdition = "";
    try {
      const raw = fs.readFileSync("/etc/os-release", "utf8");
      const o = parseOsRelease(raw);
      if (o.PRETTY_NAME) osName = o.PRETTY_NAME;
      if (o.VERSION_ID) osVersion = o.VERSION_ID;
      if (o.ID) osEdition = o.ID;
    } catch {
      // ignore
    }
    return {
      osFamily: "Linux",
      osName,
      osVersion,
      osEdition,
      buildNumber: "",
      manufacturer: "",
      model: "",
      platform,
    };
  }

  return {
    osFamily: "Unknown",
    osName: os.type(),
    osVersion: os.release(),
    osEdition: "",
    buildNumber: "",
    manufacturer: "",
    model: "",
    platform,
  };
}

function pickBaselineFilenameForSystem(system: {
  osFamily: string;
  buildNumber: string;
  osVersion: string;
  osEdition: string;
}): { subDir: string; filename: string } {
  if (system.osFamily === "Windows") {
    const build = parseInt(system.buildNumber || "0", 10);
    if (!isNaN(build) && build >= 26100) {
      return { subDir: "windows", filename: "msft_windows_11_24h2_machine.json" };
    }
    if (!isNaN(build) && build >= 22621) {
      return { subDir: "windows", filename: "msft_windows_11_22h2_machine.json" };
    }
    return { subDir: "windows", filename: "msft_windows_10_22h2_machine.json" };
  }

  if (system.osFamily === "Linux") {
    const distro = String(system.osEdition || "").toLowerCase();
    const ver = String(system.osVersion || "");
    if (distro.includes("ubuntu") && ver.startsWith("24.04")) {
      return { subDir: "linux", filename: "cis_ubuntu_2404_machine.json" };
    }
    if (distro.includes("debian") && ver.startsWith("12")) {
      return { subDir: "linux", filename: "cis_debian_12_machine.json" };
    }
    if (distro.includes("fedora") && ver.startsWith("40")) {
      return { subDir: "linux", filename: "cis_fedora_40_machine.json" };
    }
    if (distro.includes("arch")) {
      return { subDir: "linux", filename: "cis_arch_machine.json" };
    }
    return { subDir: "linux", filename: "cis_ubuntu_2404_machine.json" };
  }

  if (system.osFamily === "macOS") {
    const major = String(system.osVersion || "");
    if (major === "15") return { subDir: "macos", filename: "cis_macos_sequoia_machine.json" };
    return { subDir: "macos", filename: "cis_macos_sonoma_machine.json" };
  }

  return { subDir: "", filename: "" };
}

function loadBaselineFromDisk(subDir: string, filename: string): BaselineFile {
  if (!subDir || !filename) {
    return { findings: [] };
  }

  const candidates: string[] = [];
  candidates.push(path.join(process.cwd(), "data", "baselines", subDir, filename));

  const resourcesPath = (process as any).resourcesPath ? String((process as any).resourcesPath) : "";
  if (resourcesPath) {
    candidates.push(path.join(resourcesPath, "data", "baselines", subDir, filename));
  }

  let p = "";
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      p = c;
      break;
    }
  }

  if (!p) {
    throw new Error(`Baseline introuvable: ${candidates.join(" | ")}`);
  }

  const raw = fs.readFileSync(p, "utf8");
  const parsed = JSON.parse(raw);
  return parsed as BaselineFile;
}

function applyBaselineVariants(baseline: BaselineFile, system: { osEdition: string; manufacturer: string }) {
  const baseFindings = Array.isArray(baseline.findings) ? baseline.findings : [];
  const variants = baseline.variants || {};

  const editionKey = system.osEdition || "";
  const manufacturer = (system.manufacturer || "").toLowerCase();

  const excluded = new Set<string>();
  const additional: any[] = [];

  if (editionKey && variants[editionKey]?.excludeFindings) {
    for (const id of variants[editionKey]!.excludeFindings!) excluded.add(String(id));
  }

  const vendorKeys = Object.keys(variants).filter((k) => k && k !== "Home" && k !== "Pro" && k !== "Enterprise" && k !== "Education");
  for (const key of vendorKeys) {
    if (manufacturer && manufacturer.includes(key.toLowerCase())) {
      if (variants[key]?.excludeFindings) {
        for (const id of variants[key]!.excludeFindings!) excluded.add(String(id));
      }
      if (variants[key]?.additionalFindings) {
        additional.push(...(variants[key]!.additionalFindings || []));
      }
    }
  }

  const findings = baseFindings
    .filter((f: any) => !excluded.has(String(f?.id)))
    .concat(additional);

  return findings;
}

function parseRecommendedOperator(
  operator: string | undefined,
  recommendedValue: string | undefined,
): { operator: string; recommended: string } {
  const op = String(operator || "").trim();
  const rec = String(recommendedValue ?? "").trim();
  if (op) return { operator: op, recommended: rec };

  const m = rec.match(/^(>=|<=|!=|>|<)\s*(.+)$/);
  if (m) return { operator: m[1], recommended: String(m[2] || "").trim() };

  return { operator: "=", recommended: rec };
}

function compareValues(current: string, recommended: string, operator: string | undefined): boolean {
  const op = String(operator || "=").trim().toLowerCase();

  const curTrim = String(current ?? "").trim();
  const recTrim = String(recommended ?? "").trim();

  if (op === "contains") {
    return curTrim.toLowerCase().includes(recTrim.toLowerCase());
  }

  const curNum = Number(curTrim);
  const recNum = Number(recTrim);
  const bothNumeric = !Number.isNaN(curNum) && !Number.isNaN(recNum);

  if (bothNumeric) {
    if (op === ">=") return curNum >= recNum;
    if (op === "<=") return curNum <= recNum;
    if (op === ">") return curNum > recNum;
    if (op === "<") return curNum < recNum;
    if (op === "!=") return curNum !== recNum;
    return curNum === recNum;
  }

  const curLow = curTrim.toLowerCase();
  const recLow = recTrim.toLowerCase();

  if (op === "!=") return curLow !== recLow;
  if (op === ">=") return curLow >= recLow;
  if (op === "<=") return curLow <= recLow;
  if (op === ">") return curLow > recLow;
  if (op === "<") return curLow < recLow;
  return curLow === recLow;
}

async function getCurrentValueWindows(finding: any): Promise<{ currentValue: string; skipReason?: string }> {
  const method = String(finding?.method || "");

  try {
    if (method.toLowerCase() === "registry") {
      const regPath = String(finding?.registryPath || "");
      const regItem = String(finding?.registryItem || "");
      if (!regPath || !regItem) return { currentValue: "Non configuré", skipReason: "registry_not_configured" };

      const cmd = `try { $v=(Get-ItemProperty -Path \"${regPath.replace(/\"/g, "\\\"")}\" -Name \"${regItem.replace(/\"/g, "\\\"")}\" -ErrorAction Stop).${regItem}; Write-Output $v } catch { Write-Output "__NOT_SET__" }`;
      const out = await execPowerShell(cmd);
      if (out.includes("__NOT_SET__")) {
        const def = finding?.defaultValue != null ? String(finding.defaultValue) : "";
        if (def) return { currentValue: def };
        return { currentValue: "Non configuré", skipReason: "registry_not_configured" };
      }
      return { currentValue: out };
    }

    if (method.toLowerCase() === "service") {
      const svc = String(finding?.methodArgument || "");
      if (!svc) return { currentValue: "Service inconnu", skipReason: "service_not_installed" };
      const cmd = `try { $s=Get-Service -Name \"${svc.replace(/\"/g, "\\\"")}\" -ErrorAction Stop; Write-Output $s.StartType } catch { Write-Output "__NOT_INSTALLED__" }`;
      const out = await execPowerShell(cmd);
      if (out.includes("__NOT_INSTALLED__")) {
        return { currentValue: "Service non installé", skipReason: "service_not_installed" };
      }
      return { currentValue: out };
    }

    if (method.toLowerCase() === "accountpolicy") {
      const out = await execPowerShell("net accounts | Out-String");
      const name = String(finding?.name || "").toLowerCase();

      const getLineValue = (regex: RegExp) => {
        const m = out.match(regex);
        return m ? String(m[1]).trim() : "";
      };

      if (name.includes("account lockout duration")) {
        const v = getLineValue(/Lockout duration\s*\(minutes\)\s*:\s*(.+)$/im);
        return v ? { currentValue: v } : { currentValue: "Non vérifié", skipReason: "account_policy_error" };
      }
      if (name.includes("account lockout threshold")) {
        const v = getLineValue(/Lockout threshold\s*:\s*(.+)$/im);
        return v ? { currentValue: v } : { currentValue: "Non vérifié", skipReason: "account_policy_error" };
      }
      if (name.includes("minimum password length")) {
        const v = getLineValue(/Minimum password length\s*:\s*(.+)$/im);
        return v ? { currentValue: v } : { currentValue: "Non vérifié", skipReason: "account_policy_error" };
      }
      if (name.includes("length of password history")) {
        const v = getLineValue(/Length of password history maintained\s*:\s*(.+)$/im);
        return v ? { currentValue: v } : { currentValue: "Non vérifié", skipReason: "account_policy_error" };
      }
      if (name.includes("maximum password age")) {
        const v = getLineValue(/Maximum password age\s*\(days\)\s*:\s*(.+)$/im);
        return v ? { currentValue: v } : { currentValue: "Non vérifié", skipReason: "account_policy_error" };
      }
      if (name.includes("minimum password age")) {
        const v = getLineValue(/Minimum password age\s*\(days\)\s*:\s*(.+)$/im);
        return v ? { currentValue: v } : { currentValue: "Non vérifié", skipReason: "account_policy_error" };
      }

      return { currentValue: "Non vérifié", skipReason: "manual_check" };
    }

    if (method.toLowerCase() === "secedit") {
      const arg = String(finding?.methodArgument || "");
      if (!arg) return { currentValue: "Non vérifié", skipReason: "manual_check" };

      const parts = arg.split("\\");
      const key = String(parts[parts.length - 1] || "").trim();
      if (!key) return { currentValue: "Non vérifié", skipReason: "manual_check" };

      const cmd = `try { $p=Join-Path $env:TEMP \"secpol_hk.cfg\"; secedit /export /cfg $p | Out-Null; $c=Get-Content -Path $p -ErrorAction Stop; $m=$c | Where-Object { $_ -match \"^${key}\s*=\s*(.+)$\" }; if ($m) { ($m -split '=')[1].Trim() } else { \"__NOT_SET__\" } } catch { \"__ERROR__\" }`;
      const out = await execPowerShell(cmd);

      if (out.includes("__ERROR__")) {
        return { currentValue: "Droits admin requis", skipReason: "admin_required" };
      }
      if (out.includes("__NOT_SET__")) {
        const def = finding?.defaultValue != null ? String(finding.defaultValue) : "";
        if (def) return { currentValue: def };
        return { currentValue: "Non configuré", skipReason: "registry_not_configured" };
      }

      return { currentValue: out };
    }

    if (method.toLowerCase() === "mppreference") {
      const arg = String(finding?.methodArgument || "").trim();
      if (!arg) return { currentValue: "Non vérifié", skipReason: "manual_check" };

      const cmd = `try { $p=Get-MpPreference; $prop=$p.PSObject.Properties[\"${arg.replace(/\"/g, "\\\"")}\"]; if ($null -eq $prop) { Write-Output "__NOT_SET__" } else { $v=$prop.Value; if ($null -eq $v) { Write-Output "__NOT_SET__" } elseif ($v -is [System.Array]) { $v | ConvertTo-Json -Compress } else { Write-Output $v } } } catch { Write-Output "__ERROR__" }`;
      const out = await execPowerShell(cmd);

      if (out.includes("__ERROR__")) {
        return { currentValue: "Droits admin requis", skipReason: "admin_required" };
      }
      if (out.includes("__NOT_SET__")) {
        const def = finding?.defaultValue != null ? String(finding.defaultValue) : "";
        if (def) return { currentValue: def };
        return { currentValue: "Non configuré", skipReason: "registry_not_configured" };
      }

      return { currentValue: out };
    }

    return { currentValue: "Non vérifié", skipReason: "manual_check" };
  } catch (e: any) {
    const msg = String(e?.message || "");
    if (msg.toLowerCase().includes("access") || msg.toLowerCase().includes("denied")) {
      return { currentValue: "Droits admin requis", skipReason: "admin_required" };
    }
    return { currentValue: "Non vérifié", skipReason: "manual_check" };
  }
}

async function getCurrentValueLinux(finding: any): Promise<{ currentValue: string; skipReason?: string }> {
  const method = String(finding?.method || "").toLowerCase();

  if (method === "command") {
    const cmd = String(finding?.command || "");
    if (!cmd) return { currentValue: "Non vérifié", skipReason: "manual_check" };
    try {
      const out = await execPosixShell(cmd);
      const trimmed = String(out || "").trim();
      // Certaines commandes "booléennes" (ex: grep -q) ne renvoient rien mais sortent avec code 0
      // Dans ce cas, on considère que la condition est vraie.
      return { currentValue: trimmed ? out : String(finding?.recommendedValue ?? "true") };
    } catch {
      return { currentValue: "Non vérifié", skipReason: "manual_check" };
    }
  }

  if (method === "file") {
    const p = String(finding?.path || "");
    const pattern = String(finding?.pattern || "");
    if (!p) return { currentValue: "Non vérifié", skipReason: "manual_check" };
    try {
      const content = fs.readFileSync(p, "utf8");
      if (pattern) {
        const ok = content.toLowerCase().includes(pattern.toLowerCase());
        return { currentValue: ok ? "configured" : "not configured" };
      }
      return { currentValue: "present" };
    } catch {
      return { currentValue: "missing" };
    }
  }

  return { currentValue: "Non vérifié", skipReason: "manual_check" };
}

async function getCurrentValueMacOS(finding: any): Promise<{ currentValue: string; skipReason?: string }> {
  const method = String(finding?.method || "").toLowerCase();

  if (method === "command") {
    const cmd = String(finding?.command || "");
    if (!cmd) return { currentValue: "Non vérifié", skipReason: "manual_check" };

    if (cmd.trim().startsWith("sudo ") && typeof (process as any).getuid === "function") {
      const uid = (process as any).getuid();
      if (uid !== 0) {
        return { currentValue: "Droits admin requis", skipReason: "admin_required" };
      }
    }

    try {
      const out = await execPosixShell(cmd);
      const trimmed = String(out || "").trim();
      // Beaucoup de checks macOS utilisent grep -q : sortie vide + exit code 0 = succès
      return { currentValue: trimmed ? out : String(finding?.recommendedValue ?? "true") };
    } catch {
      return { currentValue: "Non vérifié", skipReason: "manual_check" };
    }
  }

  if (method === "defaults") {
    const domain = String(finding?.domain || "");
    const key = String(finding?.key || "");
    if (!domain || !key) return { currentValue: "Non vérifié", skipReason: "manual_check" };

    const cmd = `defaults read ${JSON.stringify(domain)} ${JSON.stringify(key)} 2>/dev/null || echo '__NOT_SET__'`;
    try {
      const out = await execPosixShell(cmd);
      if (out.includes("__NOT_SET__")) {
        return { currentValue: "Non configuré", skipReason: "registry_not_configured" };
      }
      if (!String(out || "").trim()) {
        return { currentValue: "Non vérifié", skipReason: "manual_check" };
      }
      return { currentValue: out };
    } catch {
      return { currentValue: "Non vérifié", skipReason: "manual_check" };
    }
  }

  return { currentValue: "Non vérifié", skipReason: "manual_check" };
}

function normalizeFinding(raw: any): ScanFinding {
  return {
    id: String(raw?.id || ""),
    name: String(raw?.name || ""),
    category: String(raw?.category || ""),
    method: String(raw?.method || ""),
    severity: String(raw?.severity || ""),
    recommendedValue: raw?.recommendedValue != null ? String(raw.recommendedValue) : undefined,
    defaultValue: raw?.defaultValue != null ? String(raw.defaultValue) : undefined,
    operator: raw?.operator != null ? String(raw.operator) : undefined,
    description: raw?.description != null ? String(raw.description) : undefined,
    risk: raw?.risk != null ? String(raw.risk) : undefined,
    compatibility: raw?.compatibility != null ? String(raw.compatibility) : undefined,
    remediation: raw?.remediation,
    currentValue: raw?.currentValue != null ? String(raw.currentValue) : undefined,
    skipReason: raw?.skipReason != null ? String(raw.skipReason) : undefined,
  };
}

export async function POST() {
  try {
    const system = await detectSystemInfo();

    const { subDir, filename } = pickBaselineFilenameForSystem(system);

    const baselineFile = loadBaselineFromDisk(subDir, filename);
    const applicableRawFindings = applyBaselineVariants(baselineFile, system);

    const findings: ScanResult["findings"] = [];

    for (const raw of applicableRawFindings) {
      const f = normalizeFinding(raw);

      let status: "pass" | "fail" | "unknown" = "unknown";
      let currentValue = f.currentValue || "";
      let skipReason = f.skipReason;

      if (system.osFamily === "Windows") {
        const cur = await getCurrentValueWindows(raw);
        currentValue = cur.currentValue;
        skipReason = cur.skipReason;

        if (!skipReason && f.recommendedValue != null) {
          const pr = parseRecommendedOperator(f.operator, String(f.recommendedValue));
          const ok = compareValues(currentValue, pr.recommended, pr.operator);
          status = ok ? "pass" : "fail";
        } else {
          status = "unknown";
        }
      } else if (system.osFamily === "Linux") {
        const cur = await getCurrentValueLinux(raw);
        currentValue = cur.currentValue;
        skipReason = cur.skipReason;

        if (!skipReason && f.recommendedValue != null) {
          const pr = parseRecommendedOperator(f.operator, String(f.recommendedValue));
          const inferredOp = f.operator ? pr.operator : (Number.isNaN(Number(currentValue)) ? "contains" : pr.operator);
          const ok = compareValues(currentValue, pr.recommended, inferredOp);
          status = ok ? "pass" : "fail";
        } else {
          status = "unknown";
        }
      } else if (system.osFamily === "macOS") {
        const cur = await getCurrentValueMacOS(raw);
        currentValue = cur.currentValue;
        skipReason = cur.skipReason;

        if (!skipReason && f.recommendedValue != null) {
          const pr = parseRecommendedOperator(f.operator, String(f.recommendedValue));
          const ok = compareValues(currentValue, pr.recommended, pr.operator);
          status = ok ? "pass" : "fail";
        } else {
          status = "unknown";
        }
      } else {
        status = "unknown";
        currentValue = "Non supporté";
        skipReason = "manual_check";
      }

      findings.push({
        ...f,
        currentValue,
        skipReason,
        status,
      });
    }

    const payload: ScanResult = {
      system: {
        osFamily: system.osFamily,
        osName: system.osName,
        osVersion: system.osVersion,
        osEdition: system.osEdition,
        buildNumber: system.buildNumber,
        manufacturer: system.manufacturer,
        model: system.model,
      },
      baseline: filename,
      totalFindings: findings.length,
      findings,
    };

    return NextResponse.json(payload);
  } catch (e: any) {
    return NextResponse.json(
      {
        error: String(e?.message || e),
      },
      { status: 500 },
    );
  }
}
