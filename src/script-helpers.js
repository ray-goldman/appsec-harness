'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { stripComments, maskStrings, detectLanguage } = require('./languages');
const { computedDataOnly } = require('./js-computed');
const { javascriptCommandSafe } = require('./js-command-proofs');

const IDENT = '[A-Za-z_][A-Za-z0-9_]*';
const NUMERIC_SQL = /^(?:SELECT|UPDATE|DELETE|INSERT)\b[A-Za-z0-9_ .,*=<>]*[=<>]\s*$/i;
const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Only indexes admitted, local source files. Never imports target modules.
function buildScriptProject(files, complete) {
  const entries = new Map();
  let bytes = 0;
  for (const file of files) {
    // Unsupported script syntax can still mutate a shared runtime namespace.
    if (!/\.(?:js|py)$/.test(file.rel)) {
      if (['javascript', 'typescript', 'python'].includes(detectLanguage(file.rel))) complete = false;
      continue;
    }
    if (entries.size >= 2000 || (bytes += file.size) > 8 * 1024 * 1024) { complete = false; break; }
    try {
      const raw = fs.readFileSync(file.abs, 'utf8');
      const lang = file.rel.endsWith('.py') ? 'python' : 'javascript';
      if (raw.includes('\0') || raw.length > 100000) { complete = false; continue; }
      const code = stripComments(raw, lang).replace(/\r\n/g, '\n');
      entries.set(file.rel, { file: file.rel, raw, code, mask: maskStrings(code, lang), lang });
    } catch { complete = false; }
  }
  const sources = [...entries.values()];
  const indexedComplete = complete;
  // Dynamic namespace edits can invalidate either built-in or module identity.
  if (sources.some(s => /\b(?:eval|setattr|getattr|globals|locals|vars|__dict__|__builtins__|builtins|globalThis|Reflect)\b|\bObject\s*\.\s*(?:defineProperty|assign)|\bglobal\s*\.|\bFunction\s*\(|\brequire\s*\.\s*(?:cache|extensions)|\bModule\s*\.\s*_load|\bmodule\s*\.\s*constructor|\bfrom\b[^\n]*\bimport\s*\*/.test(s.code) ||
      (s.lang === 'python' && (/\bexec\s*\(/.test(s.code) || /[^\x00-\x7f]|\f|\v/.test(s.mask))) ||
      (s.lang === 'javascript' && (/\bwith\s*\(|\.\s*constructor\b|\b(?:global|window|self)\b/.test(s.mask) ||
        [...s.mask.matchAll(/\bthis\b/g)].some(m => !/^\s*\.\s*[A-Za-z_$]/.test(s.mask.slice(m.index + 4))))))) complete = false;
  return { entries, complete, indexedComplete, sources, proofs: 0 };
}

function builtin(entry, name, project) {
  if (!entry || !project.complete || /\\u[0-9a-fA-F{]/.test(entry.raw)) return false;
  // Sloppy CommonJS assignments in another module can replace globals.
  const owners = entry.lang === 'javascript' ? project.sources.filter(s => s.lang === 'javascript') : [entry];
  for (const owner of owners) {
    if (/\\u[0-9a-fA-F{]/.test(owner.raw)) return false;
    for (const m of owner.mask.matchAll(new RegExp(`\\b${name}\\b`, 'g'))) {
      if (!/^\s*\(/.test(owner.mask.slice(m.index + name.length)) ||
          /(?:\.|\bdef|\bfunction|\bclass)\s*$/.test(owner.mask.slice(0, m.index))) return false;
    }
  }
  return !project.sources.some(s => new RegExp(`\\b${name}\\s*\\.|\\b(?:global|nonlocal)\\s+${name}\\b`).test(s.mask));
}

function resolveModule(project, file, specifier, python) {
  if (specifier.length > 200 || specifier.includes('\\') || specifier.includes('\0')) return null;
  let candidates;
  if (python) {
    if (!/^[A-Za-z_]\w*$/.test(specifier)) return null;
    candidates = [path.posix.join(path.posix.dirname(file), specifier + '.py'), specifier + '.py'];
    if ([...project.entries.keys()].some(f => f.endsWith(`/${specifier}/__init__.py`) || f === `${specifier}/__init__.py`)) return null;
  } else {
    if (!specifier.startsWith('./') || !/^[./A-Za-z0-9_-]+$/.test(specifier)) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
    candidates = base.endsWith('.js') ? [base] : [base + '.js', base + '/index.js'];
  }
  const matches = [...new Set(candidates)].filter(f => !f.startsWith('../') && project.entries.has(f));
  return matches.length === 1 ? project.entries.get(matches[0]) : null;
}

function pythonFunction(entry, name) {
  // Do not try to recover the beginning of a multiline decorator expression.
  if (entry.mask.includes('@')) return null;
  const lines = entry.code.split('\n');
  const maskedLines = entry.mask.split('\n');
  const re = new RegExp(`^def ${escape(name)}\\((${IDENT})\\):\\s*$`);
  const defs = lines.map((line, i) => re.test(line) && re.test(maskedLines[i]) ? i : -1).filter(i => i >= 0);
  if (defs.length !== 1) return null;
  const start = defs[0], declaration = lines[start].match(re);
  if (lines.slice(0, start).filter(s => s.trim()).at(-1)?.trim().startsWith('@')) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    if (!/^ +\S/.test(lines[i])) break;
    if (/^\s*(?:""" *"""|''' *''')\s*$/.test(maskedLines[i])) continue; // one-line docstring
    body.push(lines[i].trim());
  }
  if (body.length !== 1 || !body[0].startsWith('return ')) return null;
  // Definitions with a later assignment, alias/escape, or duplicate definition
  // cannot borrow this body. Calls are allowed, bare references are not.
  const occurrences = [...entry.mask.matchAll(new RegExp(`\\b${escape(name)}\\b`, 'g'))];
  if (occurrences.some(m => !/^\s*\(/.test(entry.mask.slice(m.index + name.length)))) return null;
  if ([...entry.mask.matchAll(new RegExp(`\\b(?:def|class)\\s+${escape(name)}\\b`, 'g'))].length !== 1) return null;
  return { parameter: declaration[1], expression: body[0].slice(7) };
}

function importedHelper(entry, callee, project) {
  if (!project.complete) return null;
  if (entry.lang === 'python') {
    const m = callee.match(new RegExp(`^(${IDENT})\\.(${IDENT})$`));
    if (!m) return null;
    const [_, alias, name] = m;
    const imports = [...entry.code.matchAll(new RegExp(`^import (${IDENT})(?: as (${IDENT}))?\\s*$`, 'gm'))]
      .filter(i => (i[2] || i[1]) === alias && entry.mask.slice(i.index, i.index + i[0].length) === i[0]);
    if (imports.length !== 1) return null;
    // Every non-import alias use must be a simple member read, not a store,
    // argument escape, parameter declaration or alias of the module.
    const masked = entry.mask.slice(0, imports[0].index) +
      ' '.repeat(imports[0][0].length) + entry.mask.slice(imports[0].index + imports[0][0].length);
    if ([...masked.matchAll(new RegExp(`\\b${escape(alias)}\\b`, 'g'))].some(r =>
      !new RegExp(`^\\s*\\.\\s*${IDENT}\\b(?!\\s*(?:=(?!=)|\\+=|:))`).test(masked.slice(r.index + alias.length)))) return null;
    const owner = resolveModule(project, entry.file, imports[0][1], true);
    if (!owner) return null;
    if (project.sources.some(s => [...s.mask.matchAll(new RegExp(`\\.\\s*${escape(name)}\\b`, 'g'))]
      .some(use => !/^\s*\(/.test(s.mask.slice(use.index + use[0].length))))) return null;
    if (project.sources.some(s => new RegExp(`\\.\\s*${escape(name)}\\s*(?:=|\\+=|:|,)|\\bdel\\s+[^\\n]*\\b${escape(name)}\\b|__code__|__getattribute__`).test(s.code))) return null;
    const fn = pythonFunction(owner, name);
    return fn ? { owner, ...fn } : null;
  }
  if (!new RegExp(`^${IDENT}$`).test(callee)) return null;
  if (!builtin(entry, 'require', project)) return null;
  const imports = [...entry.code.matchAll(new RegExp(`^const\\s*\\{\\s*${escape(callee)}\\s*\\}\\s*=\\s*require\\((["'])([^"'\\n]+)\\1\\);\\s*$`, 'gm'))];
  if (imports.length !== 1) return null;
  const owner = resolveModule(project, entry.file, imports[0][2], false);
  if (!owner) return null;
  let references = 0;
  for (const source of project.sources.filter(s => s.lang === 'javascript')) {
    const calls = [...source.code.matchAll(/\brequire\s*\(/g)];
    const literals = [...source.code.matchAll(/\brequire\s*\(\s*(["'])([^"'\n]+)\1\s*\)/g)];
    if (calls.length !== literals.length) return null;
    for (const loaded of literals) {
      const dependency = resolveModule(project, source.file, loaded[2], false);
      // Unresolved imports may alias this module or replace its cached export.
      // This proof requires a closed set of supported local dependencies.
      if (!dependency) return null;
      if (dependency === owner) references++;
    }
    if (/\bimport\b/.test(source.mask)) return null;
  }
  // A second importer could mutate the cached export before this binding.
  if (references !== 1) return null;
  const definition = new RegExp(`^function ${escape(callee)}\\((${IDENT})\\) \\{ return ([^;\\n{}]+); \\}\\s*$`, 'gm');
  const defs = [...owner.code.matchAll(definition)];
  if (defs.length !== 1) return null;
  const exportRe = new RegExp(`^module\\.exports = \\{ ${escape(callee)} \\};\\s*$`, 'm');
  if (!exportRe.test(owner.code) || owner.code.replace(definition, '').replace(exportRe, '').trim()) return null;
  const remaining = entry.mask.slice(0, imports[0].index) + ' '.repeat(imports[0][0].length) + entry.mask.slice(imports[0].index + imports[0][0].length);
  if ([...remaining.matchAll(new RegExp(`\\b${escape(callee)}\\b`, 'g'))].some(r =>
    !/^\s*\(/.test(remaining.slice(r.index + callee.length)) ||
    /(?:function|class|\.)\s*$/.test(remaining.slice(0, r.index)))) return null;
  return { owner, parameter: defs[0][1], expression: defs[0][2] };
}

function scriptSinkFilter(file, project, callArgs) {
  const entry = project.entries.get(file);
  if (!entry || !project.complete || /\t|\\u[0-9a-fA-F{]|\\\r?\n/.test(entry.raw)) return () => false;
  const python = entry.lang === 'python', lines = entry.code.split('\n');
  // Computed properties can retrieve callable values. The optional bounded
  // syntax proof must establish they stay data before relaxing this fallback.
  if (!python && project.sources.some(s => s.lang === 'javascript' && s.mask.includes('[')) &&
      !computedDataOnly(project)) return () => false;
  const previous = i => { while (--i >= 0) if (lines[i].trim()) return i; return -1; };
  const indent = line => line.length - line.trimStart().length;
  function fullCall(expression) {
    const m = expression.trim().match(new RegExp(`^(${IDENT}(?:\\.${IDENT})?)\\s*\\(`));
    if (!m || expression.length > 1000) return null;
    const text = expression.trim(), args = callArgs(text, m[0].length);
    // A balanced outer call must consume the whole expression.
    const mask = maskStrings(text, entry.lang);
    let depth = 1, i = m[0].length;
    for (; i < mask.length && depth; i++) {
      if (mask[i] === '(') depth++;
      else if (mask[i] === ')') depth--;
    }
    return !depth && i === text.length ? { callee: m[1], args } : null;
  }
  function numeric(expression) {
    const call = fullCall(expression);
    if (!call || call.args.length !== 1) return false;
    const conversion = python ? 'int' : 'Number';
    if (call.callee === conversion) return builtin(entry, conversion, project);
    const helper = importedHelper(entry, call.callee, project);
    return !!helper && helper.expression === `${conversion}(${helper.parameter})` &&
      builtin(helper.owner, conversion, project);
  }
  function numericBinding(name, line) {
    if (python && (!indent(lines[line]) ||
        new RegExp(`\\b(?:global|nonlocal)\\s+[^\\n]*\\b${escape(name)}\\b`).test(entry.mask))) return false;
    const prior = previous(line);
    if (prior < 0 || indent(lines[prior]) !== indent(lines[line])) return false;
    const re = python
      ? new RegExp(`^\\s*${escape(name)} = (.+)$`)
      : new RegExp(`^\\s*const ${escape(name)} = (.+);\\s*$`);
    const declaration = lines[prior].match(re);
    if (!declaration || !numeric(declaration[1])) return false;
    // No outer conditional body or continuation may turn the adjacent text
    // into a different execution scope.
    const before = previous(prior);
    if (!python && before >= 0 && /\b(?:if|for|while|with)\b[^{};]*$/.test(lines[before])) return false;
    return true;
  }
  function sql(argument, line) {
    let m;
    if (python) {
      m = argument.trim().match(new RegExp(`^(["'])([^"'\\\\\\n]*)%d\\1\\s*%\\s*(${IDENT})$`));
    } else {
      m = argument.trim().match(new RegExp(`^(["'])([^"'\\\\\\n]*)\\1\\s*\\+\\s*(${IDENT})$`));
    }
    return !!m && NUMERIC_SQL.test(m[2]) && numericBinding(m[3], line);
  }
  function hostnameGuard(argument, line) {
    const arg = argument.trim().match(new RegExp(`^(["'])([A-Za-z0-9_./ -]+ )\\1\\s*\\+\\s*(${IDENT})$`));
    if (!arg || !python) return false;
    const ret = previous(line), guard = previous(ret);
    if (guard < 0 || indent(lines[guard]) !== indent(lines[line]) ||
        indent(lines[ret]) !== indent(lines[line]) + 4 ||
        !/^\s*return\s+(?:"[^"\\]*"|'[^'\\]*'|None)(?:,\s*\d+)?\s*$/.test(lines[ret])) return false;
    const match = lines[guard].trim().match(new RegExp(`^if not (${IDENT}\\.${IDENT})\\(${escape(arg[3])}\\):$`));
    if (!match) return false;
    const assignment = previous(guard);
    const assigned = assignment < 0 ? null : lines[assignment].match(new RegExp(`^\\s*${escape(arg[3])} = (.+)$`));
    if (!assigned || !indent(lines[line]) || indent(lines[assignment]) !== indent(lines[line]) ||
        new RegExp(`\\b(?:global|nonlocal)\\s+[^\\n]*\\b${escape(arg[3])}\\b`).test(entry.mask)) return false;
    if (!requestString(assigned[1])) return false;
    const helper = importedHelper(entry, match[1], project);
    if (!helper) return false;
    if ([...project.entries.keys()].some(f => /(?:^|\/)re(?:\.py|\/__init__\.py)$/.test(f))) return false;
    const imported = [...helper.owner.mask.matchAll(/^import re\s*$/gm)];
    if (imported.length !== 1 || helper.parameter === 're') return false;
    const withoutImport = helper.owner.mask.slice(0, imported[0].index) +
      ' '.repeat(imported[0][0].length) + helper.owner.mask.slice(imported[0].index + imported[0][0].length);
    if ([...withoutImport.matchAll(/\bre\b/g)].some(m =>
      !/^\s*\.fullmatch\s*\(/.test(withoutImport.slice(m.index + 2)))) return false;
    // A second re import can alias/escape the shared module and change its
    // callable identity. Only this owner's checked import is supported.
    if (project.sources.some(s => s.code.split('\n').some(text =>
        /^\s*(?:from|import)\b/.test(text) && /\bre\b/.test(text) &&
        (s !== helper.owner || text.trim() !== 'import re')) ||
        /\.\s*(?:fullmatch|re)\s*(?:=|:|,)|sys\s*\.\s*modules|__import__|importlib/.test(s.code))) return false;
    return helper.expression === `re.fullmatch(r"[A-Za-z0-9.-]{1,253}", ${helper.parameter}) is not None`;
  }
  function requestString(expression) {
    // A regex match does not prove safe concatenation for an arbitrary str
    // subclass. Accept only the modeled Flask request-string source, directly
    // or through a source-resolved one-return helper.
    let owner = entry, value = expression;
    const literal = `(?:"[A-Za-z0-9_-]+"|'[A-Za-z0-9_-]+')`;
    const call = fullCall(expression);
    if (call && !call.callee.startsWith('request.')) {
      if (call.args.length !== 1 || !new RegExp(`^${literal}$`).test(call.args[0])) return false;
      const helper = importedHelper(entry, call.callee, project);
      if (!helper) return false;
      owner = helper.owner;
      value = helper.expression.replace(new RegExp(`\\b${escape(helper.parameter)}\\b`, 'g'), '"key"');
    }
    if (!new RegExp(`^request\\.args(?:\\[${literal}\\]|\\.get\\(${literal}(?:,\\s*(?:""|'')\\s*)?\\))$`).test(value)) return false;
    const imports = [...owner.mask.matchAll(/^from flask import request\s*$/gm)];
    if (imports.length !== 1) return false;
    const rest = owner.mask.slice(0, imports[0].index) + ' '.repeat(imports[0][0].length) +
      owner.mask.slice(imports[0].index + imports[0][0].length);
    if ([...rest.matchAll(/\brequest\b/g)].some(m => !/^\s*\.args\b/.test(rest.slice(m.index + 7)))) return false;
    if ([...project.entries.keys()].some(f => /(?:^|\/)flask(?:\.py|\/__init__\.py)$/.test(f))) return false;
    return !project.sources.some(s => /\b(?:__radd__|__add__|__str__|__class__|__getattr__|__getattribute__|metaclass)\b|\.\s*args\b(?!\s*(?:\.get\s*\(|\[))/.test(s.mask));
  }
  return (ruleId, line, window) => {
    if (!python && ruleId === 'JS-CMDI-001') return javascriptCommandSafe(file, line, project);
    if (window.includes('\n') || window.length > 2000) return false;
    const sqlRule = /^(?:JS|PY)-SQLI-00[123]$/.test(ruleId);
    const commandRule = ruleId === 'PY-CMDI-001';
    if (!sqlRule && !commandRule) return false;
    if (++project.proofs > 128) return false;
    const re = commandRule
      ? /\bsubprocess\.(?:check_output|check_call|run)\s*\(/g
      : /\.(?:query|execute|executemany|executescript|raw|unsafe|extra|mogrify)\s*\(/g;
    const matches = [...window.matchAll(re)];
    if (matches.length !== 1 || /;\s*\S/.test(window)) return false;
    const m = matches[0], args = callArgs(window, m.index + m[0].length);
    const prefix = window.slice(0, m.index).trim();
    if (commandRule ? !/^(?:return)?$/.test(prefix) :
        !new RegExp(`^(?:return\\s+)?${IDENT}$`).test(prefix)) return false;
    if (sqlRule) return args.length === 1 && sql(args[0], line);
    // Additional arguments can have side effects; accept only shell=True.
    return args.length === 2 && args[1].trim() === 'shell=True' && hostnameGuard(args[0], line);
  };
}

module.exports = { buildScriptProject, scriptSinkFilter };
