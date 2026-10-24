'use strict';
const path = require('path');
const ADVISORIES = require('./advisories');
const { parseManifest, LOCKFILES } = require('./manifests');
const { inRange, floorOfSpec } = require('../util');
const { analyzeCargo } = require('./cargo');
const CARGO_SNAPSHOT = require('./cargo-advisories.json');
const { inCargoRange } = require('./cargo-semver');
const { scanSecrets } = require('../rules/secrets');

const OSV_ECO = { npm: 'npm', pypi: 'PyPI', maven: 'Maven', go: 'Go', rubygems: 'RubyGems', composer: 'Packagist', nuget: 'NuGet', 'crates.io': 'crates.io' };

const index = new Map();
for (const a of [...ADVISORIES, ...CARGO_SNAPSHOT.advisories]) {
  const k = `${a.eco}:${a.name.toLowerCase()}`;
  if (!index.has(k)) index.set(k, []);
  index.get(k).push(a);
}

function matchAdvisories(dep) {
  if (dep.eco === 'crates.io' && (!dep.publicRegistry || dep.resolution !== 'locked')) return [];
  const list = index.get(`${dep.eco}:${dep.name.toLowerCase()}`);
  if (!list) return [];
  const hits = [];
  for (const a of list) {
    if (dep.version) {
      if (a.ranges.some((r) => dep.eco === 'crates.io' ? inCargoRange(dep.version,r) : inRange(dep.version, r))) hits.push({ a, exact: true });
    } else if (dep.spec) {
      if (a.ranges.some((r) => r.any)) { hits.push({ a, exact: false }); continue; }
      if (a.malicious) continue; // exact-version advisories cannot be judged from a range
      const floor = floorOfSpec(dep.spec);
      if (floor && a.ranges.some((r) => inRange(floor, r))) hits.push({ a, exact: false });
    }
  }
  return hits;
}

/**
 * files: [{ rel, raw }] for every manifest/lockfile found by the walker.
 * Returns { findings, inventory }.
 */
function analyzeSupplyChain(files) {
  const findings = [];
  const inventory = [];
  const cargo = analyzeCargo(files.filter(f => /(?:^|\/)Cargo\.(?:toml|lock)$/.test(f.rel)));
  const byDir = new Map();
  for (const f of files) {
    if (/(?:^|\/)Cargo\.(?:toml|lock)$/.test(f.rel)) continue;
    const dir = path.posix.dirname(f.rel);
    if (!byDir.has(dir)) byDir.set(dir, new Set());
    byDir.get(dir).add(path.posix.basename(f.rel));
  }

  for (const f of files) {
    const parsed = parseManifest(f.rel, f.raw);
    if (/(?:^|\/)Cargo\.(?:toml|lock)$/.test(f.rel)) continue;
    if (!parsed) continue;
    const dir = path.posix.dirname(f.rel);
    const siblings = byDir.get(dir) || new Set();
    // A lockfile next to a manifest is authoritative: skip range-based guesses from the manifest.
    const hasLock = parsed.manifestFor && (LOCKFILES[parsed.manifestFor] || []).some((l) => siblings.has(l));

    for (const h of parsed.hygiene) findings.push({ ...h, file: f.rel, source: 'supply' });

    if (parsed.manifestFor === 'npm' && !hasLock) {
      let raw = {};
      try { raw = JSON.parse(f.raw || '{}'); } catch { /* malformed */ }
      const hasDeps = Object.keys(raw.dependencies || {}).length > 0;
      if (hasDeps) {
        findings.push({ ruleId: 'SUPPLY-LOCK-001', file: f.rel, line: 1, severity: 'low', source: 'supply',
          message: 'No lockfile committed: every install resolves fresh versions, so a malicious publish is picked up immediately and builds are not reproducible.',
          detail: 'package.json without package-lock.json / yarn.lock / pnpm-lock.yaml' });
      }
    }

    const agg = new Map();
    for (const dep of parsed.deps) {
      if (dep.version == null && hasLock) continue;
      inventory.push(dep);
      for (const { a, exact } of matchAdvisories(dep)) {
        // One finding per (file, package, advisory); extra installed copies are listed in `detail`.
        const key = `${dep.name}|${a.ids.join()}`;
        if (agg.has(key)) { const g = agg.get(key); g.versions.add(dep.version || dep.spec); g.count++; continue; }
        const fixed = a.ranges.map((r) => r.fixed).filter(Boolean);
        const g = { versions: new Set([dep.version || dep.spec]), count: 1, finding: null };
        agg.set(key, g);
        g.finding = ({
          ruleId: a.malicious ? 'SUPPLY-MAL-001' : 'SUPPLY-VULN-001',
          file: f.rel, line: dep.line, source: 'supply',
          severity: exact ? a.severity : (a.severity === 'critical' ? 'high' : a.severity),
          confidence: exact ? 'high' : 'low',
          cwe: a.cwe, cves: a.ids,
          title: a.malicious ? `Known-malicious package version: ${dep.name}@${dep.version || dep.spec}` : `${dep.name}@${dep.version || dep.spec} — ${a.ids.join(', ')}`,
          message: `${a.summary}${exact ? '' : ` (declared range \`${dep.spec}\` permits an affected version; confirm against the lockfile)`}`,
          fix: a.malicious ? 'Remove/replace this version immediately, rotate any credentials present where it was installed, and audit for persistence.'
            : fixed.length ? `Upgrade ${dep.name} to a fixed release (${fixed.join(' / ')} or later on your line).` : `Remove or replace ${dep.name}; no fixed version exists.`,
          detail: `${dep.eco}:${dep.name}@${dep.version || dep.spec}`,
          package: { eco: dep.eco, name: dep.name, version: dep.version, spec: dep.spec, direct: !!dep.direct, dev: !!dep.dev },
        });
      }
    }
    for (const g of agg.values()) {
      if (g.count > 1) g.finding.detail = `${g.finding.package.eco}:${g.finding.package.name} — ${g.count} installed copies: ${[...g.versions].join(', ')}`;
      findings.push(g.finding);
    }
  }
  inventory.push(...cargo.inventory);
  for (const dep of cargo.inventory) for (const { a } of matchAdvisories(dep)) findings.push({
    ruleId: 'SUPPLY-VULN-001', file:dep.file, line:dep.line, source:'supply', severity:a.severity, confidence:'high',
    cwe:a.cwe, cves:a.ids, title:`${dep.name}@${dep.version} — ${a.ids.join(', ')}`,
    message:a.summary + ' Presence in the lockfile does not establish runtime reachability.',
    fix:'Upgrade to a patched release listed in the advisory; check compatibility on your release line.',
    refs:a.refs, detail:`crates.io:${dep.name}@${dep.version}`, package:{eco:dep.eco,name:dep.name,version:dep.version},
  });
  return { findings, inventory, cargo };
}

// Optional online enrichment. Sends only (ecosystem, name, version) tuples — never source code.
async function queryOsv(inventory, { timeoutMs = 20000, maxDetails = 300 } = {}) {
  const exact = inventory.filter((d) => d.version && OSV_ECO[d.eco] && (d.eco !== 'crates.io' || (d.publicRegistry && d.resolution === 'locked')));
  for(const d of exact)if(d.eco==='crates.io'){
    const tuple=JSON.stringify({name:d.name,version:d.version});
    if(scanSecrets('osv-package-identity.txt',tuple,[tuple]).length)throw new Error('OSV query withheld: Cargo package identity contains a detected secret or credential');
  }
  const uniq = new Map();
  const cargoCopies = new Map();
  for(const d of exact)if(d.eco==='crates.io'){const k=`${d.eco}|${d.name}|${d.version}`;if(!cargoCopies.has(k))cargoCopies.set(k,[]);cargoCopies.get(k).push(d);}
  for (const d of exact) uniq.set(`${d.eco}|${d.name}|${d.version}`, d);
  const deps = [...uniq.values()];
  const results = [];
  for (let i = 0; i < deps.length; i += 1000) {
    const chunk = deps.slice(i, i + 1000);
    const body = { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: OSV_ECO[d.eco] }, version: d.version })) };
    const res = await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`);
    const j = await res.json();
    if(!Array.isArray(j.results)||j.results.length!==chunk.length)throw new Error('OSV incomplete response cardinality');
    if(j.results.some(r=>r.next_page_token))throw new Error('OSV incomplete response: pagination requires another query');
    if(j.results.some(r=>r.vulns!=null&&(!Array.isArray(r.vulns)||r.vulns.length>1000||r.vulns.some(v=>typeof v.id!=='string'||! /^[A-Za-z0-9._-]{1,128}$/.test(v.id)))))throw new Error('OSV incomplete or invalid advisory identities');
    (j.results || []).forEach((r, k) => { for (const v of r.vulns || []) results.push({ dep: chunk[k], id: v.id }); });
  }
  const ids = [...new Set(results.map((r) => r.id))].slice(0, maxDetails);
  if(results.some(r=>r.dep.eco==='crates.io'&&!ids.includes(r.id)))throw new Error('OSV incomplete: Cargo advisory detail limit reached');
  const details = new Map();
  await Promise.all(ids.map(async (id) => {
    try {
      const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(timeoutMs) });
      if (r.ok) details.set(id, await r.json());
    } catch { /* best effort */ }
  }));
  return results.flatMap(({ dep, id }) => {
    const d = details.get(id) || {};
    if(dep.eco==='crates.io' && (d.id!==id||d.withdrawn||!Array.isArray(d.affected)||!d.affected.some(a=>a.package?.name===dep.name&&a.package?.ecosystem==='crates.io')))throw new Error('OSV incomplete: Cargo advisory identity/details could not be verified');
    const sev = (d.database_specific && d.database_specific.severity || '').toLowerCase();
    const severity = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' }[sev] || (id.startsWith('MAL-') ? 'critical' : 'medium');
    const aliases = (d.aliases || []).filter((a) => a.startsWith('CVE-'));
    const finding = {
      ruleId: id.startsWith('MAL-') ? 'SUPPLY-MAL-001' : 'SUPPLY-OSV-001', file: dep.file, line: dep.line, source: 'osv', severity, confidence: 'high',
      cves: [id, ...aliases], title: `${dep.name}@${dep.version} — ${id}${aliases.length ? ' (' + aliases.join(', ') + ')' : ''}`,
      message: d.summary || (d.details || '').split('\n')[0].slice(0, 300) || `Listed in OSV as ${id}.`,
      fix: 'See advisory for fixed versions.', refs: [`https://osv.dev/vulnerability/${id}`],
      detail: `${dep.eco}:${dep.name}@${dep.version}`, package: { eco: dep.eco, name: dep.name, version: dep.version },
    };
    return dep.eco==='crates.io'?cargoCopies.get(`${dep.eco}|${dep.name}|${dep.version}`).map(copy=>({...finding,file:copy.file,line:copy.line})):finding;
  });
}

module.exports = { analyzeSupplyChain, queryOsv, ADVISORIES, CARGO_SNAPSHOT };
