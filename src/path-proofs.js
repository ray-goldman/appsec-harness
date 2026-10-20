'use strict';
const { maskStrings } = require('./languages');
const { shadowsType } = require('./java-methods');

// Narrow lexical path proofs, not filesystem/symlink or authorization proofs.
// Match whole bounded method bodies so extra control flow and writes fail closed.
function pathSinkFilter({ file, lang, raw, code, project }) {
  const safe = new Set(), unknown = () => false;
  if (!['java', 'go'].includes(lang) || code.length > 100000 || /[^\x00-\x7f]|\\u|\x00/.test(raw)) return unknown;
  if (lang === 'java' ? !code.includes('.normalize()') || !code.includes('Files.readAllBytes(') :
      !code.includes('filepath.IsLocal(') || !code.includes('os.ReadFile(')) return unknown;
  const mask = maskStrings(code, lang), stack = [], blocks = new Map(), depths = new Uint16Array(mask.length);
  for (let i = 0; i < mask.length; i++) {
    depths[i] = stack.length;
    if (mask[i] === '{') { if (stack.length >= 64) return unknown; stack.push(i); }
    if (mask[i] === '}') {
      const start = stack.pop();
      if (start === undefined) return unknown;
      blocks.set(start, i);
    }
  }
  if (stack.length) return unknown;
  const lineAt = offset => code.slice(0, offset).split('\n').length - 1;
  function mark(start, end, needle) {
    const offset = code.indexOf(needle, start);
    if (offset < start || offset >= end) return;
    const line = lineAt(offset), text = code.split('\n')[line];
    // Do not suppress another operation sharing a source line.
    if (offset - text.indexOf(needle) >= start && offset - text.indexOf(needle) + text.length <= end) safe.add(line);
  }
  if (lang === 'java') {
    const index = project?.byFile.get(file)?.index;
    if (!project?.complete || project.reflective || !index?.complete ||
        /\b(?:extends|implements)\b|\bimport\s+static\b/.test(mask)) return unknown;
    if (index.imports.has('String') && index.imports.get('String') !== 'java.lang.String') return unknown;
    if ([...project.classes.keys()].some(key => key.split('.').pop() === 'String')) return unknown;
    for (const name of ['Path', 'Paths', 'Files']) {
      if (name !== 'Path' && shadowsType(index, name, project)) return unknown;
      let uses = 0;
      if (name !== 'Path') for (const use of mask.matchAll(new RegExp(`\\b${name}\\b`, 'g'))) {
        if (++uses > 256) return unknown;
        const before = mask.slice(Math.max(0, use.index - 100), use.index), after = mask.slice(use.index + name.length);
        if (/\bimport\s+java\.nio\.file\.$/.test(before) && /^\s*;/.test(after)) continue;
        if (!/^\s*\./.test(after) || /\.\s*$/.test(before)) return unknown;
      }
      if ([...project.classes.keys()].some(key => key.split('.').pop() === name)) return unknown;
      if (index.imports.has(name) ? index.imports.get(name) !== `java.nio.file.${name}` :
          !/\bimport\s+java\.nio\.file\.\*\s*;/.test(mask)) return unknown;
    }
    const header = /^[ \t]*(?:public|private|protected)\s+byte\[\]\s+[A-Za-z_]\w*\(\s*(?:@RequestParam\s+)?String\s+([A-Za-z_]\w*)\s*\)\s+throws\s+IOException\s*\{/gm;
    for (const m of mask.matchAll(header)) {
      const open = m.index + m[0].length - 1, end = blocks.get(open);
      if (depths[open] !== 1 || end === undefined || end - open > 4000) continue;
      const body = code.slice(open + 1, end);
      const proof = body.match(/^\s*Path\s+(?<value>[A-Za-z_]\w*)\s*=\s*(?<base>[A-Za-z_]\w*)\.resolve\((?<input>[A-Za-z_]\w*)\)\.normalize\(\);\s*if\s*\(!\k<value>\.startsWith\(\k<base>\)\)\s*throw new SecurityException\("[^"\\\n]*"\);\s*return Files\.readAllBytes\(\k<value>\);\s*$/);
      if (!proof || proof.groups.input !== m[1]) continue;
      const { value, base, input } = proof.groups;
      if (new Set([value, base, input]).size !== 3) continue;
      const roots = [...code.matchAll(new RegExp(`\\bprivate static final Path ${base} = Paths\\.get\\("(/[A-Za-z0-9_/-]+)"\\)\\.toAbsolutePath\\(\\);`, 'g'))];
      if (roots.length !== 1 || depths[roots[0].index] !== 1 || roots[0][1].includes('//') ||
          !mask.startsWith(`private static final Path ${base}`, roots[0].index)) continue;
      mark(open + 1, end, `Path ${value}`);
      mark(open + 1, end, 'return Files.readAllBytes');
    }
  } else {
    // Standard-library imports must own these identifiers in this file.
    const imports = [];
    for (const m of code.matchAll(/^import\s+(?:\(([\s\S]{0,8000}?)\)|("[^"\n]+"))/gm)) {
      if (depths[m.index] !== 0 || !mask.startsWith('import', m.index)) continue;
      for (const line of (m[1] || m[2]).split('\n').filter(s => s.trim())) {
        const item = line.trim().match(/^(?:([A-Za-z_]\w*|\.)\s+)?"([^"\\]+)"$/);
        if (!item || item[1] === '.') return unknown;
        imports.push({ name: item[1] || item[2].split('/').pop(), spec: item[2] });
      }
    }
    for (const [name, spec] of [['filepath', 'path/filepath'], ['os', 'os'], ['http', 'net/http']]) {
      const owners = imports.filter(item => item.name === name);
      if (owners.length !== 1 || owners[0].spec !== spec) return unknown;
      if (new RegExp(`\\b(?:var|const|type|func)\\s+${name}\\b|\\b${name}\\s*:?=`).test(mask)) return unknown;
    }
    const header = /^func\s+[A-Za-z_]\w*\(w http\.ResponseWriter, r \*http\.Request\)\s*\{/gm;
    for (const m of mask.matchAll(header)) {
      const open = m.index + m[0].length - 1, end = blocks.get(open);
      if (depths[open] !== 0 || end === undefined || end - open > 4000) continue;
      const body = code.slice(open + 1, end);
      const proof = body.match(/^\s*(?<name>[A-Za-z_]\w*) := filepath\.Base\(r\.URL\.Query\(\)\.Get\("[^"\\\n]*"\)\)\s+if !filepath\.IsLocal\(\k<name>\)\s*\{\s*return\s*\}\s+(?<data>[A-Za-z_]\w*), _ := os\.ReadFile\(filepath\.Join\((?<root>[A-Za-z_]\w*), \k<name>\)\)\s+w\.Write\(\k<data>\)\s*$/);
      if (!proof) continue;
      const { name, data, root } = proof.groups;
      if (new Set([name, data, root, 'w', 'r', 'os', 'filepath', 'http']).size !== 8) continue;
      const roots = [...code.matchAll(new RegExp(`^const ${root} = "(/[A-Za-z0-9_/-]+)"\\s*$`, 'gm'))];
      if (roots.length !== 1 || depths[roots[0].index] !== 0 || roots[0][1].includes('//') ||
          !mask.startsWith(`const ${root} = "`, roots[0].index)) continue;
      mark(open + 1, end, `${data}, _ := os.ReadFile`);
    }
  }
  return (rule, line) => rule === (lang === 'java' ? 'JAVA-PATH-001' : 'GO-PATH-001') && safe.has(line);
}
module.exports = { pathSinkFilter };
