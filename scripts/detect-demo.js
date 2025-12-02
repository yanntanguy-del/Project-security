// Simple detection demo harness (Node)
// Reads baseline JSONs and runs a simplified selection algorithm.
const fs = require('fs');
const path = require('path');

function normalizeWindowsDetection(osObj = {}, editionId = '', hwObj = {}) {
  try {
    const caption = osObj.Caption || osObj.caption || 'Microsoft Windows';
    const version = osObj.Version || osObj.version || '';
    const build = osObj.BuildNumber || osObj.Build || osObj.buildNumber || '';
    const editionRaw = editionId || osObj.EditionID || osObj.Edition || '';
    const manufacturer = hwObj.Manufacturer || hwObj.manufacturer || '';
    const model = hwObj.Model || hwObj.model || hwObj.Product || '';
    const ed = String(editionRaw || '').toLowerCase();
    let normEdition = '';
    if (ed.includes('pro')) normEdition = 'Pro'; else if (ed.includes('enterprise')) normEdition = 'Enterprise'; else if (ed.includes('home')) normEdition = 'Home'; else if (ed.includes('core')) normEdition = 'Core'; else if (ed.includes('education')) normEdition = 'Education'; else normEdition = String(editionRaw || '');
    const osFamily = caption && String(caption).toLowerCase().includes('windows') ? 'windows' : 'unknown';
    return { osFamily, osName: String(caption || 'Microsoft Windows'), osVersion: String(version || ''), osBuild: String(build || ''), osEdition: normEdition, manufacturer: manufacturer || undefined, model: model || undefined };
  } catch (e) {
    return { osFamily: 'unknown', osName: 'unknown', osVersion: '', osBuild: '', osEdition: '' };
  }
}

function loadFindingsFromBaselines() {
  const baseDir = path.join(process.cwd(), 'data', 'baselines', 'windows');
  const findings = [];
  if (!fs.existsSync(baseDir)) return findings;
  const files = fs.readdirSync(baseDir).filter(f => f.toLowerCase().endsWith('.json'));
  for (const file of files) {
    try {
      const raw = fs.readFileSync(path.join(baseDir, file), 'utf8');
      const j = JSON.parse(raw);
      const rows = Array.isArray(j) ? j : (j.rows || j.findings || j.items || []);
      for (const r of rows) {
        const id = r.id || r.ID || `hk-${file}-${Math.random().toString(36).slice(2,8)}`;
        const name = r.name || r.Name || r.Title || `HK ${id}`;
        const recommended = r.RecommendedValue || r.recommendedValue || r.Recommended || '';
        const category = r.Category || r.category || '';
        const remediationVariants = [];
        if (r.registryPath && r.registryItem) remediationVariants.push({ method: 'registry', instruction: `Set ${r.registryItem} at ${r.registryPath} to ${recommended}`, edition: r.Edition || undefined, manufacturer: r.Vendor || r.Manufacturer || undefined });
        else if (recommended) remediationVariants.push({ method: 'note', instruction: `${r.method || (r.raw && r.raw.Method) || 'Apply setting'}: set to ${recommended}`, edition: r.Edition || undefined, manufacturer: r.Vendor || r.Manufacturer || undefined });
        else remediationVariants.push({ method: 'note', instruction: r.Name || r.Title || 'Apply recommended configuration' });
        findings.push({ id: `HK-${id}`, name, description: r.Description || r.description || '', category, severity: (r.Severity || r.severity || 'Medium'), recommended, applicable: { osFamily: ['windows'] }, remediationVariants });
      }
    } catch (e) {
      // ignore
    }
  }
  // add a small builtin example if none
  if (findings.length === 0) {
    findings.push({ id: 'WIN-FW-001', name: 'Windows Firewall - All Profiles Enabled', category: 'Network & Firewall', severity: 'High', recommended: 'Enable firewall for Domain, Private and Public profiles', applicable: { osFamily: ['windows'] }, remediationVariants: [{ edition: 'Pro', method: 'gui', instruction: 'Settings → Privacy & Security → Windows Security → Firewall & network protection → Enable all profiles' }, { method: 'note', instruction: 'Use `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True` in PowerShell' }] });
  }
  return findings;
}

function selectFindingsForSystem(findings, detected) {
  const edition = (detected.osEdition || '').toLowerCase();
  const vendor = (detected.manufacturer || '').toLowerCase();
  const filtered = findings.filter(f => {
    const app = f.applicable || {};
    if (app.osFamily && detected.osFamily && !app.osFamily.includes(detected.osFamily)) return false;
    if (app.editions && detected.osEdition) {
      const norm = detected.osEdition.toLowerCase();
      if (!app.editions.some(e => e.toLowerCase() === norm || norm.includes(e.toLowerCase()))) return false;
    }
    if (app.manufacturers && detected.manufacturer) {
      const m = detected.manufacturer.toLowerCase();
      if (!app.manufacturers.some(x => m.includes(x.toLowerCase()))) return false;
    }
    return true;
  });

  return filtered.map(f => ({ f, score: ((f.remediationVariants || []).reduce((s, v) => s + ((v.edition && v.edition.toLowerCase().includes(edition)) ? 20 : 0) + ((v.manufacturer && vendor && v.manufacturer.toLowerCase().includes(vendor)) ? 15 : 0), 0)) })).sort((a,b) => b.score - a.score).map(x => x.f);
}

function getRemediationForFinding(f, detected) {
  if (!f.remediationVariants || f.remediationVariants.length === 0) return null;
  const edition = (detected.osEdition || '').toLowerCase();
  const manufacturer = (detected.manufacturer || '').toLowerCase();
  let best = null;
  let bestScore = -1;
  for (const v of f.remediationVariants) {
    let s = 0;
    if (v.edition && edition && v.edition.toLowerCase() === edition) s += 30;
    if (v.manufacturer && manufacturer && manufacturer.includes((v.manufacturer || '').toLowerCase())) s += 20;
    if (s === 0) s = 1;
    if (s > bestScore) { bestScore = s; best = v; }
  }
  return best;
}

// Simulate detection output
const osObj = { Caption: 'Microsoft Windows 11 Pro', Version: '10.0.22621', BuildNumber: '22621' };
const editionId = 'Pro';
const hwObj = { Manufacturer: 'Dell Inc.', Model: 'XPS 15' };

const detected = normalizeWindowsDetection(osObj, editionId, hwObj);
const findings = loadFindingsFromBaselines();
const selected = selectFindingsForSystem(findings, detected).slice(0, 10);

console.log('Detected system:');
console.log(JSON.stringify(detected, null, 2));
console.log('---');
console.log('Total findings in library:', findings.length);
console.log('Top selected findings (up to 10):');
for (let i = 0; i < Math.min(3, selected.length); i++) {
  const f = selected[i];
  const best = getRemediationForFinding(f, detected);
  console.log(`- ${f.id} | ${f.name} | ${f.severity}`);
  console.log(`  Recommended: ${f.recommended}`);
  if (best) {
    console.log(`  Suggested remediation: ${best.instruction}`);
    console.log(`  Variant reason: ${best.edition ? `edition=${best.edition}` : ''} ${best.manufacturer ? `manufacturer=${best.manufacturer}` : ''}`);
  }
}

console.log('--- demo finished');
