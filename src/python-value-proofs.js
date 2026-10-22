'use strict';
// Static, bounded lexical evidence. Unsupported syntax keeps the original finding.
const path = require('node:path');
const { tokenize, logicalStatements, sourceLines } = require('./python-log-evidence');
const DYNAMIC = /\b(?:exec|eval|compile|getattr|setattr|delattr|globals|locals|vars|builtins|inspect|_getframe|global|nonlocal|__\w*__|context_processor|template_global|template_filter|jinja_env|jinja_loader|render_template_string|stream_template|stream_template_string|Environment|Blueprint|jinja2|Template|_render|get_template|get_or_select_template)\b/;
const id = t => t?.kind === 'id';
const op = (t, value) => t?.kind === 'op' && t.value === value;
const literal = t => t?.kind === 'string' && !t.prefix && !t.triple && !t.escaped;
const text = ts => ts.map(t => t.value).join('');

function analyze(entry) {
  // Module identity/path constants are ordinary data; reflective attributes are not.
  if (!entry || DYNAMIC.test(entry.code.replace(/\b(?:__name__|__file__|__main__)\b/g, ''))) return null;
  const tokens = tokenize(entry.code);
  if (!tokens || tokens.some((t, i) => op(t, ';') || t.value === 'import' && op(tokens[i + 1], '*') ||
      t.kind === 'string' && /f/i.test(t.prefix) && /[^\x00-\x7f]/.test(t.value))) return null;
  const locations = sourceLines(entry.code), statements = logicalStatements(tokens);
  const info = statements.map(ts => {
    const line = locations.at(ts[0].start), prefix = entry.code.slice(locations.starts[line], ts[0].start);
    return { ts, line, indent: /^ *$/.test(prefix) ? prefix.length : -1, owner: null };
  });
  if (info.some(s => s.indent < 0)) return null;
  let owner = null;
  for (const s of info) {
    if (s.indent === 0) {
      owner = null;
      if (s.ts[0]?.value === 'def' && id(s.ts[1]) && text(s.ts.slice(2)) === '():') {
        owner = { header: s, body: [], valid: true };
      }
    } else if (owner) {
      if (s.ts.some(t => id(t) && ['def', 'class', 'lambda', 'yield', 'await'].includes(t.value))) owner.valid = false;
      owner.body.push(s); s.owner = owner;
    }
  }
  return { entry, tokens, statements: info, locations };
}

function model(project) {
  if (!project?.indexedComplete) return null;
  if (!project.pythonValues) project.pythonValues = new Map();
  return project.pythonValues;
}
function fileModel(file, project) {
  const cache = model(project);
  if (!cache) return null;
  if (!cache.has(file)) cache.set(file, analyze(project.entries.get(file)));
  return cache.get(file);
}
function mentionsOtherFormat(data, names, admitted = new Set()) {
  return data.tokens.some(t => t.kind === 'string' && /f/i.test(t.prefix) && !admitted.has(t) &&
    names.some(name => new RegExp(`\\b${name}\\b`).test(t.value)));
}
function onlyUses(data, name, admitted) {
  return data.tokens.every(t => !id(t) || t.value !== name || admitted.has(t));
}

function sqlLines(data) {
  const safe = new Set(); let candidates = 0;
  for (let n = 2; n < data.statements.length; n++) {
    const [map, choice, query] = data.statements.slice(n - 2, n + 1);
    if (!query.owner?.valid || map.owner !== query.owner || choice.owner !== query.owner ||
        map.indent !== choice.indent || choice.indent !== query.indent) continue;
    const m = map.ts, c = choice.ts, q = query.ts;
    if (!id(m[0]) || !op(m[1], '=') || !op(m[2], '{') || !op(m.at(-1), '}') || m.length > 135) continue;
    if (++candidates > 64) return new Set();
    let count = 0, valid = true;
    for (let i = 3; i < m.length - 1; i += 4) {
      if (!literal(m[i]) || !op(m[i + 1], ':') || !literal(m[i + 2]) ||
          i + 3 < m.length - 1 && !op(m[i + 3], ',')) { valid = false; break; }
      count++;
    }
    if (!valid || !count || count > 32 || !id(c[0]) || !op(c[1], '=') || c.length !== 10 ||
        !id(c[2]) || c[2].value !== m[0].value || text(c.slice(3, 6)) !== '.get(' ||
        !id(c[6]) || !op(c[7], ',') || !literal(c[8]) || !op(c[9], ')')) continue;
    const format = q[2];
    if (q.length !== 3 || !id(q[0]) || !op(q[1], '=') || format?.kind !== 'string' ||
        format.prefix?.toLowerCase() !== 'f' || format.triple || format.escaped ||
        !/^(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(format.value)) continue;
    const substitutions = [...format.value.matchAll(/\{([A-Za-z_]\w*)\}/g)];
    if (!substitutions.length || substitutions.length > 16 || substitutions.some(s => s[1] !== c[0].value) ||
        /[{}]/.test(format.value.replace(/\{[A-Za-z_]\w*\}/g, ''))) continue;
    if (data.locations.lines[query.line].trim() !== data.entry.code.slice(q[0].start, format.end).trim()) continue;
    if (new Set([m[0].value, c[0].value, q[0].value]).size !== 3 ||
        !onlyUses(data, m[0].value, new Set([m[0], c[2]])) ||
        !onlyUses(data, c[0].value, new Set([c[0]])) ||
        mentionsOtherFormat(data, [m[0].value, c[0].value, q[0].value], new Set([format]))) continue;
    const uses = data.tokens.filter(t => id(t) && t.value === q[0].value && t !== q[0]);
    if (!uses.length || uses.length > 64 || uses.some(t => {
      const i = data.tokens.indexOf(t);
      return !op(data.tokens[i - 1], '(') || !id(data.tokens[i - 2]) ||
        !['execute', 'executemany', 'executescript'].includes(data.tokens[i - 2].value) ||
        !op(data.tokens[i - 3], '.') || ![',', ')'].includes(data.tokens[i + 1]?.value);
    })) continue;
    safe.add(query.line);
    for (const use of uses) {
      const statement = data.statements.find(s => s.ts.includes(use));
      const ts = statement?.ts;
      // A line-wide finding may cover another sink or an effectful extra argument.
      if (ts?.length === 6 && id(ts[0]) && op(ts[1], '.') && id(ts[2]) &&
          ['execute', 'executemany', 'executescript'].includes(ts[2].value) && op(ts[3], '(') && ts[4] === use && op(ts[5], ')') &&
          data.locations.lines[statement.line].trim() === data.entry.code.slice(ts[0].start, ts.at(-1).end).trim()) safe.add(statement.line);
    }
  }
  return safe;
}
function pythonSqlConstantLine(file, project, line) {
  if (!project?.indexedComplete || [...project.entries.values()].some(s => s.lang === 'python' && !fileModel(s.file, project))) return false;
  const data = fileModel(file, project);
  if (!data) return false;
  data.sql ??= sqlLines(data);
  return data.sql.has(line);
}

function argumentsOf(tokens, open) {
  const args = [[]]; let depth = 1, end = open + 1;
  for (; end < tokens.length; end++) {
    const t = tokens[end]; if (t.kind === 'newline') continue;
    if (op(t, '(') || op(t, '[') || op(t, '{')) depth++;
    if (op(t, ')') || op(t, ']') || op(t, '}')) depth--;
    if (!depth) return { args: args.at(-1).length ? args : args.slice(0, -1), end };
    if (op(t, ',') && depth === 1) args.push([]); else args.at(-1).push(t);
  }
  return null;
}
function constantBinding(data, call, expression, reads, labels) {
  if (expression.length === 1 && literal(expression[0])) return true;
  if (expression.length !== 1 || !id(expression[0])) return false;
  const name = expression[0].value;
  const statement = data.statements.find(s => s.ts.includes(call));
  const owner = statement?.owner;
  if (!owner?.valid) return false;
  const writes = owner.body.filter(s => id(s.ts[0]) && s.ts[0].value === name && op(s.ts[1], '='));
  if (!writes.length || writes.some(s => s.ts.length !== 3 || !literal(s.ts[2]))) return false;
  if (writes[0].indent !== 4 || writes[0].ts[0].start >= call.start) return false;
  const permitted = new Set([...writes.map(s => s.ts[0]), ...reads.filter(t => t.value === name), ...labels.filter(t => t.value === name)]);
  return onlyUses(data, name, permitted) && !mentionsOtherFormat(data, [name]);
}
function templateBindings(project) {
  const cache = model(project); if (!cache) return null;
  const bindings = new Map(); let appFile = null;
  if ([...project.entries.keys()].some(f => /(?:^|\/)(?:flask|jinja2)(?:\.py|\/)/i.test(f))) return null;
  const sources = [...project.entries.values()].filter(s => s.lang === 'python');
  if (sources.length !== 1) return null;
  for (const source of sources) {
    const data = fileModel(source.file, project); if (!data) return null;
    if (data.tokens.some(t => t.kind === 'string' && /f/i.test(t.prefix) && /\brender_template\b/.test(t.value))) return null;
    if (/\b(?:template_folder|loader|template_rendered|before_render_template|send|render|stream|update_template_context)\b/.test(source.code)) return null;
    const ts = data.tokens.filter(t => t.kind !== 'newline');
    const flask = data.statements.filter(s => s.indent === 0 && s.ts[0]?.value === 'from' && s.ts[1]?.value === 'flask' && s.ts[2]?.value === 'import');
    const imported = new Set();
    for (const s of flask) {
      const names = s.ts.slice(3);
      if (names.some((t, i) => i % 2 ? !op(t, ',') : !id(t) || ['as', 'from', 'import'].includes(t.value))) return null;
      for (const t of names) if (id(t)) imported.add(t);
    }
    const renderImports = [...imported].filter(t => t.value === 'render_template');
    if (ts.some(t => id(t) && t.value === 'render_template') && renderImports.length !== 1) return null;
    const apps = data.statements.filter(s => text(s.ts.slice(1)) === '=Flask(__name__)' && id(s.ts[0]) && s.indent === 0);
    if (apps.length) {
      if (apps.length !== 1 || appFile !== null || ![...imported].some(t => t.value === 'Flask')) return null;
      appFile = source.file;
      const flaskUses = ts.filter(t => id(t) && t.value === 'Flask' && !imported.has(t));
      if (flaskUses.length !== 1 || flaskUses[0] !== apps[0].ts[2]) return null;
      const appName = apps[0].ts[0].value;
      for (let i = 0; i < ts.length; i++) if (id(ts[i]) && ts[i].value === appName && ts[i] !== apps[0].ts[0]) {
        if (!op(ts[i + 1], '.') || !['route', 'run'].includes(ts[i + 2]?.value) || !op(ts[i + 3], '(')) return null;
      }
      for (const s of data.statements.filter(s => op(s.ts[0], '@'))) {
        const d = s.ts;
        if (d.length !== 7 || d[1]?.value !== appName || !op(d[2], '.') || d[3]?.value !== 'route' || !op(d[4], '(') || !literal(d[5]) || !op(d[6], ')')) return null;
      }
    }
    const calls = [], labels = []; let bindingsChecked = 0;
    for (let i = 0; i < ts.length; i++) {
      const t = ts[i];
      if (!id(t) || t.value !== 'render_template' || imported.has(t)) continue;
      if (!op(ts[i + 1], '(') || op(ts[i - 1], '.') || ['def', 'class'].includes(ts[i - 1]?.value)) return null;
      const call = argumentsOf(ts, i + 1);
      if (!call || calls.length >= 64 || call.args.length > 33 || !literal(call.args[0]?.[0]) || call.args[0].length !== 1 || !/^[A-Za-z0-9_/-]+\.html$/.test(call.args[0][0].value)) return null;
      const kwargs = new Map();
      for (const a of call.args.slice(1)) {
        if (!id(a[0]) || !op(a[1], '=') || a.length < 3 || kwargs.has(a[0].value)) return null;
        kwargs.set(a[0].value, a.slice(2));
        labels.push(a[0]);
      }
      calls.push({ token: t, name: call.args[0][0].value, kwargs });
    }
    const reads = calls.flatMap(c => [...c.kwargs.values()].filter(v => v.length === 1 && id(v[0])).flat());
    for (const c of calls) {
      bindingsChecked += c.kwargs.size; if (bindingsChecked > 128) return null;
      const key = path.posix.join(path.posix.dirname(source.file), 'templates', c.name);
      if (!bindings.has(key)) bindings.set(key, []);
      bindings.get(key).push(new Set([...c.kwargs].filter(([, expression]) => constantBinding(data, c.token, expression, reads, labels)).map(([name]) => name)));
    }
  }
  if (appFile === null) return null;
  // Only default, single-file Flask apps are admitted. Other render owners stay unknown.
  for (const key of bindings.keys()) if (!key.startsWith(path.posix.join(path.posix.dirname(appFile), 'templates') + '/')) return null;
  return bindings;
}
function templateTags(raw) {
  const tags = []; let cursor = 0;
  while (true) {
    const start = raw.indexOf('{%', cursor); if (start < 0) return tags;
    const end = raw.indexOf('%}', start + 2);
    if (end < 0 || tags.length >= 256) return null;
    const tag = raw.slice(start + 2, end);
    if (tag.length > 2000 || tag.includes('{%')) return null;
    tags.push(tag); cursor = end + 2;
  }
}
function pythonTemplateConstantLine(file, raw, line, project) {
  if (!model(project) || Buffer.byteLength(raw) > 200000) return false;
  project.pythonTemplateProofCount = (project.pythonTemplateProofCount || 0) + 1;
  if (project.pythonTemplateProofCount > 128) return false;
  if (project.pythonTemplateBindings === undefined) project.pythonTemplateBindings = templateBindings(project);
  const calls = project.pythonTemplateBindings?.get(file);
  if (!calls?.length) return false;
  const tags = templateTags(raw); if (!tags) return false;
  // No template-level rebinding, composition, custom filters or inheritance proof.
  for (const tag of tags) {
    if (!/^\s*(?:if\b[^{}()]*|elif\b[^{}()]*|else|endif|for\b[^{}()]*|endfor)\s*$/.test(tag)) return false;
  }
  const row = raw.split(/\r?\n/)[line] || '';
  const outputs = [...row.matchAll(/\{\{\s*([A-Za-z_]\w*)\s*\|\s*safe\s*\}\}/g)];
  if (!outputs.length || /<%-|\{\{\{|\{!!|!=|\{%/.test(row.replace(/\{\{\s*[A-Za-z_]\w*\s*\|\s*safe\s*\}\}/g, ''))) return false;
  if (/\|\s*safe\b/i.test(row.replace(/\{\{\s*[A-Za-z_]\w*\s*\|\s*safe\s*\}\}/g, ''))) return false;
  for (const [, name] of outputs) {
    if (calls.some(set => !set.has(name))) return false;
    for (const tag of tags) {
      if (/^\s*for\b/.test(tag) && new RegExp(`\\b${name}\\b`).test(tag.split(/\bin\b/)[0])) return false;
    }
  }
  return true;
}
module.exports = { pythonSqlConstantLine, pythonTemplateConstantLine };
