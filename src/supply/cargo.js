'use strict';
const path = require('node:path').posix;
const { readToml } = require('./toml');
const { workspaceGlob } = require('./cargo-glob');
const CANONICAL = new Set(['registry+https://github.com/rust-lang/crates.io-index', 'sparse+https://index.crates.io/']);
const nameOK = s => typeof s === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(s);
const { versionOK } = require('./cargo-semver');
const specOK = s => typeof s === 'string' && s.length <= 256 && /^[0-9A-Za-z.*^~<>=+!, -]+$/.test(s) && /[0-9*]/.test(s);
function safeSource(source) {
  if (typeof source !== 'string') return null;
  // Keep package provenance, but never echo URL credentials or query/fragment values.
  return source.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi,'$1[REDACTED]@').replace(/[?#].*$/, m => m.startsWith('#') && /^#[a-f0-9]{40}$/i.test(m) ? m : '#[REDACTED]');
}
const table = obj => obj && typeof obj === 'object' && !Array.isArray(obj);
function validDeclaration(data) {
  return table(data)&&['git','path','registry','package'].every(k=>data[k]==null||typeof data[k]==='string')&&
    (data.version==null||specOK(data.version))&&(data.workspace==null||data.workspace===true)&&
    !(data.git&&data.path)&&(data.workspace===true||!!(data.version||data.git||data.path));
}

function parseCargo(file, raw) {
  const parsed = readToml(raw), deps = [], diagnostics = [...parsed.diagnostics];
  const result = { deps, hygiene: [], diagnostics };
  Object.defineProperty(result,'cargoDocument',{value:parsed,enumerable:false});
  if (!parsed.root) return result;
  const root = parsed.root;
  const diagnostic = (message, line = 1) => diagnostics.push({ code:'cargo-inventory-incomplete', line, message });
  const at = (o,key) => parsed.locations.get(o)?.get(key) || 1;
  if (path.basename(file) === 'Cargo.lock') {
    if (![2,3,4].includes(root.version)) diagnostic('Only Cargo.lock format versions 2, 3 and 4 are supported');
    if (!Array.isArray(root.package)) diagnostic('Cargo.lock has no supported package array');
    const seen = new Set();
    for (const pkg of Array.isArray(root.package) ? root.package : []) {
      if (!table(pkg) || !nameOK(pkg.name) || !versionOK(pkg.version) || (pkg.source != null && typeof pkg.source !== 'string')) { diagnostic('Invalid lock package identity'); continue; }
      const key = JSON.stringify([pkg.name,pkg.version,pkg.source]);
      if (seen.has(key)) { diagnostic('Duplicate lock package identity',at(pkg,'name')); continue; } seen.add(key);
      const publicRegistry = CANONICAL.has(pkg.source), origin = pkg.source == null ? 'local' : /^(?:registry|sparse)\+/.test(pkg.source) ? 'registry' : /^git\+/.test(pkg.source) ? 'git' : 'unknown';
      if (origin === 'unknown') diagnostic('Unsupported lock package source',at(pkg,'source'));
      if (origin === 'registry' && (typeof pkg.checksum !== 'string' || !/^[a-f0-9]{64}$/i.test(pkg.checksum))) diagnostic('Registry package has no valid SHA-256 checksum',at(pkg,'name'));
      deps.push({ eco:'crates.io', name:pkg.name, version:pkg.version, file, line:at(pkg,'name'), source:safeSource(pkg.source), checksum:typeof pkg.checksum === 'string' && /^[a-f0-9]{64}$/i.test(pkg.checksum) ? pkg.checksum : null, origin, publicRegistry, resolution:'locked', direct:null });
    }
  } else {
    if(Object.hasOwn(root,'package') && (!table(root.package)||!nameOK(root.package.name)))diagnostic('Unsupported package metadata');
    if(Object.hasOwn(root,'workspace') && (!table(root.workspace)||['members','exclude'].some(k=>root.workspace[k]!=null&&(!Array.isArray(root.workspace[k])||root.workspace[k].some(v=>typeof v!=='string')))))diagnostic('Unsupported workspace metadata');
    if(Object.hasOwn(root,'target') && (!table(root.target)||Object.values(root.target).some(v=>!table(v))))diagnostic('Unsupported target metadata');
    if(root.workspace?.dependencies && (!table(root.workspace.dependencies)||Object.values(root.workspace.dependencies).some(d=>{const data=typeof d==='string'?{version:d}:d;return !validDeclaration(data)||data.workspace;})))diagnostic('Unsupported workspace dependency declaration');
    const sections = [];
    for (const group of ['dependencies','dev-dependencies','build-dependencies']) {
      if (Object.hasOwn(root,group)) sections.push([root[group],group]);
      for (const target of Object.values(root.target || {})) if (Object.hasOwn(target,group)) sections.push([target[group],group]);
    }
    for (const [entries,group] of sections) {
      if (!table(entries)) { diagnostic('Unsupported dependency table'); continue; }
      for (const [alias, entry] of Object.entries(entries)) {
        const data = typeof entry === 'string' ? { version:entry } : entry;
        if (!validDeclaration(data) || !nameOK(alias) || !nameOK(data.package || alias)) { diagnostic('Unsupported dependency declaration',at(entries,alias)); continue; }
        const origin = data.git ? 'git' : data.path ? 'local' : 'registry';
        deps.push({ eco:'crates.io', name:data.package || alias, alias, version:null, spec:data.version || null, file, line:at(entries,alias), source:safeSource(data.git || (data.registry ? `registry:${data.registry}` : null)), origin, publicRegistry:false, direct:true, dev:group==='dev-dependencies', workspace:data.workspace===true, resolution:'requirement' });
      }
    }
    if (root.patch || root.replace) diagnostic('Source overrides are not resolved from manifests; use an authoritative lockfile');
  }
  // Reject a malformed lock as a whole: an invalid document must not mint authoritative identities.
  if (path.basename(file) === 'Cargo.lock' && diagnostics.length) deps.length = 0;
  return result;
}

function analyzeCargo(files) {
  let bytes=0;
  const inputs = files.map((f,i) => {
    const overBudget=i>=1000||(bytes+=Buffer.byteLength(f.raw))>16*1024*1024;
    const parsed=overBudget?{deps:[],diagnostics:[{line:1,code:'cargo-budget-exceeded',message:'Cargo inventory input count or byte budget exceeded'}],cargoDocument:{root:null}}:parseCargo(f.rel,f.raw);
    return {rel:f.rel,parsed};
  });
  const manifests = inputs.filter(f=>path.basename(f.rel)==='Cargo.toml');
  const byRel=new Map(manifests.map(m=>[m.rel,m])),memberships=new Map();let work=0;
  const tick=()=>{if(++work>1000000)throw Error('Cargo workspace analysis budget exceeded');};
  const incomplete=(f,message)=>f.parsed.diagnostics.push({line:1,code:'cargo-workspace-incomplete',message});
  try { for(const r of manifests.filter(m=>table(m.parsed.cargoDocument.root?.workspace))) {
    const dir=path.dirname(r.rel),w=r.parsed.cargoDocument.root.workspace;
    const compile=patterns=>{
      if(patterns==null)return [];
      if(!Array.isArray(patterns)||patterns.length>128) {incomplete(r,'Unsupported workspace pattern list');return [];}
      return patterns.flatMap(g=>{try{return [workspaceGlob(g)];}catch {incomplete(r,'Unsupported workspace member pattern');return [];}});
    };
    const declared=compile(w.members),excluded=compile(w.exclude);
    const match=(patterns,m)=>{tick();const relative=path.relative(dir,path.dirname(m.rel));return patterns.some(g=>g(relative,tick));};
    for(const pattern of declared)if(!manifests.some(m=>{tick();return pattern(path.relative(dir,path.dirname(m.rel)),tick);}))incomplete(r,'Workspace member pattern has no visible package manifest');
    const members=new Set(manifests.filter(m=>m===r||match(declared,m)&&!match(excluded,m)));
    const queue=[...members];
    for(let k=0;k<queue.length;k++) {
      const m=queue[k],root=m.parsed.cargoDocument.root;
      if(!root)continue;
      const groups=[root.dependencies,root['dev-dependencies'],root['build-dependencies'],...Object.values(root.target||{}).flatMap(t=>[t.dependencies,t['dev-dependencies'],t['build-dependencies']])];
      for(const group of groups)for(const data of Object.values(group||{}))if(table(data)&&typeof data.path==='string') {
        const rel=path.normalize(path.join(path.dirname(m.rel),data.path,'Cargo.toml'));
        tick();const member=byRel.get(rel);
        if(!member)incomplete(m,'Path dependency has no visible package manifest');
        if(member&&(dir==='.'?!rel.startsWith('../')&&!path.isAbsolute(rel):rel.startsWith(dir+'/'))&&!match(excluded,member)&&!members.has(member)) {members.add(member);queue.push(member);}
      }
    }
    memberships.set(r,members);
  }} catch {memberships.clear();for(const f of manifests)incomplete(f,'Cargo workspace analysis budget exceeded');}
  const ownerCache=new Map(),owners=[...memberships.keys()].sort((a,b)=>b.rel.length-a.rel.length);
  const workspaceRoot = m => {
    if(ownerCache.has(m))return ownerCache.get(m);
    const location=m.parsed.cargoDocument.root?.package?.workspace;
    if(typeof location==='string') {
      const requested=path.normalize(path.join(path.dirname(m.rel),location,'Cargo.toml'));
      const owner=!requested.startsWith('../')&&!path.isAbsolute(requested)?byRel.get(requested):undefined;
      if(!owner||!table(owner.parsed.cargoDocument.root?.workspace)){incomplete(m,'Explicit workspace root has no visible workspace manifest');ownerCache.set(m,undefined);return undefined;}
      ownerCache.set(m,owner);return owner;
    }
    const owner=owners.find(r=>memberships.get(r).has(m));ownerCache.set(m,owner);return owner;
  };
  const inventory=[];
  for(const f of inputs) {
    if(path.basename(f.rel)==='Cargo.lock') {
      for(const dep of f.parsed.deps) {
        if(dep.origin==='local') {
          const visible=manifests.find(m=>{const p=m.parsed.cargoDocument.root?.package;return p?.name===dep.name&&p.version===dep.version&&(path.dirname(m.rel)===path.dirname(f.rel)||workspaceRoot(m)?.rel===path.join(path.dirname(f.rel),'Cargo.toml'));});
          if(visible)dep.origin=path.dirname(visible.rel)===path.dirname(f.rel)?'root':'workspace';
        }
        inventory.push(dep);
      }
      continue;
    }
    const owner=workspaceRoot(f),dir=path.dirname(owner?.rel||f.rel),locked=inputs.find(l=>l.rel===path.join(dir,'Cargo.lock'));
    for(const dep of f.parsed.deps) {
      if(dep.workspace) {
        const inherited=owner?.parsed.cargoDocument.root?.workspace?.dependencies?.[dep.alias];
        const data=typeof inherited==='string'?{version:inherited}:inherited;
        if(!validDeclaration(data)||data.workspace||!nameOK(data.package||dep.alias))f.parsed.diagnostics.push({line:dep.line,code:'cargo-workspace-unresolved',message:'Workspace dependency inheritance could not be resolved from visible manifests'});
        else {dep.name=data.package||dep.alias;dep.spec=data.version||null;dep.origin=data.git?'git':data.path?'local':'registry';dep.source=safeSource(data.git||(data.registry?`registry:${data.registry}`:null));}
      }
      if(!locked)inventory.push(dep);
    }
  }
  return {inventory,inputs:inputs.map(f=>({file:f.rel,kind:path.basename(f.rel)==='Cargo.lock'?'lock':'manifest',status:f.parsed.diagnostics.length?'incomplete':'complete',diagnostics:f.parsed.diagnostics}))};
}

module.exports = { parseCargo, analyzeCargo, safeSource, CANONICAL };
