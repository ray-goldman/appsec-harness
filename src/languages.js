'use strict';
// Language detection, comment stripping (line-preserving) and lightweight intra-file taint tracking.
const path = require('path');
const { escapeRegExp } = require('./util');

const EXT = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.vue': 'javascript', '.svelte': 'javascript',
  '.py': 'python', '.pyw': 'python',
  '.php': 'php', '.phtml': 'php', '.php5': 'php', '.php7': 'php', '.inc': 'php',
  '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.scala': 'java', '.groovy': 'java', '.jsp': 'java',
  '.go': 'go',
  '.rb': 'ruby', '.erb': 'ruby', '.rake': 'ruby',
  '.cs': 'csharp', '.cshtml': 'csharp',
  '.rs': 'rust', // Recognition only. Rust has no source-rule/taint implementation; see coverage.source.
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
  '.html': 'html', '.htm': 'html', '.ejs': 'template', '.hbs': 'template', '.handlebars': 'template',
  '.njk': 'template', '.jinja': 'template', '.jinja2': 'template', '.j2': 'template', '.twig': 'template', '.pug': 'template',
  '.yml': 'yaml', '.yaml': 'yaml', '.json': 'json', '.toml': 'toml', '.xml': 'xml', '.properties': 'properties',
  '.tf': 'terraform', '.hcl': 'terraform', '.conf': 'conf', '.ini': 'ini', '.env': 'dotenv', '.md': 'markdown',
};

function detectLanguage(rel) {
  const base = path.basename(rel);
  if (/^Dockerfile(\..*)?$|\.dockerfile$/i.test(base) || /^Containerfile$/i.test(base)) return 'dockerfile';
  if (/^\.env(\..*)?$/.test(base)) return 'dotenv';
  if (/^nginx.*\.conf$|^.*\.nginx$/i.test(base) || /(^|\/)(nginx|sites-(available|enabled)|conf\.d)\//.test(rel)) return 'nginx';
  if (base === 'php.ini') return 'ini';
  if (/^Gemfile$|^Rakefile$/.test(base)) return 'ruby';
  if (/^Jenkinsfile$/.test(base)) return 'java';
  return EXT[path.extname(base).toLowerCase()] || null;
}

const COMMENT_STYLE = {
  javascript: { line: ['//'], block: [['/*', '*/']], strings: ['"', "'", '`'] },
  typescript: { line: ['//'], block: [['/*', '*/']], strings: ['"', "'", '`'] },
  java: { line: ['//'], block: [['/*', '*/']], strings: ['"', "'"] },
  kotlin: { line: ['//'], block: [['/*', '*/']], strings: ['"', "'"] },
  csharp: { line: ['//'], block: [['/*', '*/']], strings: ['"', "'"] },
  go: { line: ['//'], block: [['/*', '*/']], strings: ['"', "'", '`'] },
  php: { line: ['//', '#'], block: [['/*', '*/']], strings: ['"', "'"] },
  python: { line: ['#'], block: [], strings: ['"', "'"] },
  ruby: { line: ['#'], block: [], strings: ['"', "'"] },
  shell: { line: ['#'], block: [], strings: ['"', "'"] },
  yaml: { line: ['#'], block: [], strings: [] },
  dockerfile: { line: ['#'], block: [], strings: [] },
  nginx: { line: ['#'], block: [], strings: [] },
  dotenv: { line: ['#'], block: [], strings: [] },
  terraform: { line: ['#', '//'], block: [['/*', '*/']], strings: ['"'] },
};

// Replace comments with spaces, keep newlines and string literals intact so line numbers stay true.
function stripComments(text, lang) {
  const style = COMMENT_STYLE[lang];
  if (!style) return text;
  const out = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    // strings
    if (style.strings.includes(ch)) {
      // python/ruby triple quotes
      const triple = (lang === 'python') && text.startsWith(ch.repeat(3), i);
      const q = triple ? ch.repeat(3) : ch;
      out.push(q); i += q.length;
      while (i < n) {
        if (text[i] === '\\') { out.push(text[i], text[i + 1] || ''); i += 2; continue; }
        if (text.startsWith(q, i)) { out.push(q); i += q.length; break; }
        if (!triple && ch !== '`' && text[i] === '\n' && lang !== 'php') { break; } // unterminated single-line string
        out.push(text[i]); i++;
      }
      continue;
    }
    let matched = false;
    for (const lc of style.line) {
      if (text.startsWith(lc, i)) {
        // avoid treating URLs like http:// as comments, and PHP '#[' attributes
        if (lc === '//' && i > 0 && text[i - 1] === ':') break;
        if (lc === '#' && lang === 'php' && text[i + 1] === '[') break;
        if (lc === '#' && lang === 'shell' && i > 0 && /[\w$]/.test(text[i - 1])) break;
        while (i < n && text[i] !== '\n') { out.push(' '); i++; }
        matched = true; break;
      }
    }
    if (matched) continue;
    for (const [open, close] of style.block) {
      if (text.startsWith(open, i)) {
        const end = text.indexOf(close, i + open.length);
        const stop = end === -1 ? n : end + close.length;
        for (let j = i; j < stop; j++) out.push(text[j] === '\n' ? '\n' : ' ');
        i = stop; matched = true; break;
      }
    }
    if (matched) continue;
    out.push(ch); i++;
  }
  return out.join('');
}

// ---------- Taint: user-controlled input sources per language ----------
const SOURCES = {
  javascript: /\breq(?:uest)?\.(?:query|body|params|headers|cookies|signedCookies|files?|hostname|path|originalUrl|url|get\()|\bctx\.(?:query|params|headers|request\.body|request\.query)|\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b|\blocation\.(?:hash|search|href|pathname)|\bdocument\.(?:URL|referrer|cookie|location)|\bwindow\.name\b|\bsearchParams\.get\(|\bformData\.get\(|\bprocess\.argv\b|\bawait\s+(?:req|request)\.(?:json|text|formData)\(|\.getAll?\(\s*['"][^'"]+['"]\s*\)\s*\?\?/,
  python: /\brequest\.(?:args|form|values|json|data|files|cookies|headers|get_json|GET|POST|body|query_params|path_params|path_info|query_string|remote_addr|url)\b|\bsys\.argv\b|\binput\s*\(|\bflask\.request\./,
  php: /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"](?:HTTP_\w+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO)['"]|php:\/\/input|\$request->(?:input|get|query|post|all|cookie|header|file)\s*\(|\bRequest::(?:input|get|query|all)\s*\(|\bgetenv\s*\(\s*['"]HTTP_/,
  java: /\brequest\.get(?:Parameter(?:Values|Map|Names)?|Header|Headers|QueryString|Cookies|InputStream|Reader|RequestURI|PathInfo|Part|Parts)\s*\(|\b(?:ServerHttpRequest|exchange\.getRequest\(\))\.getQueryParams|\bcall\.(?:parameters|receive)/,
  kotlin: /\brequest\.get(?:Parameter|Header|QueryString)\s*\(|\bcall\.(?:parameters|receive|request\.queryParameters)/,
  go: /\br\.URL\.(?:Query\(\)|Path|RawQuery)|\br\.(?:FormValue|PostFormValue|Cookie|PathValue)\s*\(|\br\.(?:Form|PostForm|Body|Header|MultipartForm)\b|\bc\.(?:Query|Param|PostForm|DefaultQuery|DefaultPostForm|GetHeader|Cookie|FormValue|QueryParam|FormFile)\s*\(|\bc\.(?:ShouldBind\w*|Bind\w*)\s*\(|\bmux\.Vars\s*\(\s*r\s*\)|\bos\.Args\b/,
  ruby: /\bparams\b|\brequest\.(?:params|body|headers|query_string|cookies|env|raw_post|referer|url)\b|\bcookies\s*\[/,
  csharp: /\bRequest\.(?:Query|Form|Headers|Cookies|Body|QueryString)\b|\[From(?:Query|Body|Route|Form|Header)\]/,
};
SOURCES.typescript = SOURCES.javascript;

// Calls whose result is treated as validated (allow-list / sanitizer / canonicaliser). Heuristic:
// agents verify these during triage.
const SANITIZERS = /\b(?:sanitize\w*|escape\w*|validate\w*|safe\w*|clean\w*|allow(?:list|ed)\w*|whitelist\w*|encodeURIComponent|encodeURI|DOMPurify\.sanitize|path\.basename|basename|secure_filename|shlex\.quote|escapeshellarg|escapeshellcmd|htmlspecialchars|htmlentities|html\.escape|markupsafe\.escape|bleach\.clean|filepath\.Base|FilenameUtils\.getName|getName|Encode\.forHtml|StringEscapeUtils\.escape\w+|isValid\w*|is_safe_url|url_has_allowed_host_and_scheme|checkAllowed\w*|assert\w*Allowed)\s*\(/i;

// Values that neutralise taint for every sink: numeric casts.
const KILLERS = /\b(?:parseInt|parseFloat|Number|Math\.(?:floor|round|abs)|intval|floatval|int|float|Integer\.parseInt|Long\.parseLong|strconv\.Atoi|to_i|to_f|Boolean|bool|uuid\.UUID|UUID\.fromString)\s*\(/;

const ASSIGN = {
  javascript: [
    { re: /\b(?:const|let|var)\s*\{([^}=]*)\}\s*=\s*(.+)/, destructure: true },
    { re: /\b(?:const|let|var)\s*\[([^\]=]*)\]\s*=\s*(.+)/, destructure: true },
    { re: /(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)(?:\s*:\s*[\w<>\[\]|. ]+)?\s*(?:\+)?=(?![=>])\s*(.+)/ },
  ],
  python: [
    { re: /^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[\w\[\], .|]+)?\s*(?:\+)?=(?!=)\s*(.+)/, multi: true },
    { re: /\bwith\s+(.+?)\s+as\s+([A-Za-z_]\w*)/, swap: true },
    { re: /\bfor\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+in\s+(.+):/, multi: true },
  ],
  php: [{ re: /(\$[A-Za-z_]\w*)\s*(?:\.)?=(?![=>])\s*(.+)/ }],
  java: [{ re: /(?:\b[\w<>\[\],.?]+\s+)?([A-Za-z_]\w*)\s*(?:\+)?=(?!=)\s*(.+)/ }],
  kotlin: [{ re: /\b(?:val|var)\s+([A-Za-z_]\w*)(?:\s*:\s*[\w<>?]+)?\s*=\s*(.+)/ }, { re: /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*(.+)/ }],
  go: [{ re: /([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:?=(?!=)\s*(.+)/, multi: true }],
  ruby: [{ re: /(@{0,2}[A-Za-z_]\w*)\s*(?:\|\||\+)?=(?![=~>])\s*(.+)/ }],
  csharp: [{ re: /(?:\b(?:var|string|int|[\w<>\[\]]+)\s+)?([A-Za-z_]\w*)\s*(?:\+)?=(?![=>])\s*(.+?);/ }],
};
ASSIGN.typescript = ASSIGN.javascript;

// Framework parameter sources: route params that arrive as function arguments.
function frameworkParamSources(lines, lang) {
  const names = new Set();
  if (lang === 'python') {
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route)\s*\(\s*['"]([^'"]*<[^'"]+)['"]/);
      if (!m) continue;
      const params = [...m[1].matchAll(/<(?:\w+:)?(\w+)>|\{(\w+)\}/g)].map((x) => x[1] || x[2]);
      for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
        if (/^\s*(?:async\s+)?def\s+/.test(lines[j])) { params.forEach((p) => names.add(p)); break; }
      }
    }
    // FastAPI-style: def f(q: str = Query(...)) — any param with Query/Body/Form/Path/Header default
    for (const l of lines) for (const m of l.matchAll(/\b([A-Za-z_]\w*)\s*:\s*[\w\[\], |]+=\s*(?:Query|Body|Form|Path|Header|Cookie|File)\s*\(/g)) names.add(m[1]);
  }
  if (lang === 'java' || lang === 'kotlin') {
    for (const l of lines) for (const m of l.matchAll(/@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|FormParam|HeaderParam)(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:[\w<>\[\],.?]+\s+)?([A-Za-z_]\w*)\s*[,)]/g)) names.add(m[1]);
  }
  if (lang === 'csharp') {
    for (const l of lines) for (const m of l.matchAll(/\[From(?:Query|Body|Route|Form|Header)\]\s*[\w<>\[\]?]+\s+([A-Za-z_]\w*)/g)) names.add(m[1]);
  }
  return names;
}

// Blank out string-literal contents (same length) while keeping interpolated code:
// JS `${…}`, Python f"{…}", PHP "$var"/"{$…}", Ruby "#{…}", C# $"{…}". Prevents treating
// text inside SQL/HTML strings as identifiers or assignments.
function maskStrings(text, lang) {
  const out = text.split('');
  const n = text.length;
  let i = 0;
  const blank = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  while (i < n) {
    const ch = text[i];
    if (ch !== '"' && ch !== "'" && ch !== '`') { i++; continue; }
    const triple = lang === 'python' && text.startsWith(ch.repeat(3), i);
    const q = triple ? ch.repeat(3) : ch;
    const prefix = text.slice(Math.max(0, i - 3), i);
    let interp = null;
    if (ch === '`' && (lang === 'javascript' || lang === 'typescript')) interp = 'js';
    else if (lang === 'python' && /[fF][rRbB]?$|[rRbB][fF]$/.test(prefix)) interp = 'brace';
    else if (lang === 'csharp' && /\$@?$|@\$$/.test(prefix)) interp = 'brace';
    else if (lang === 'php' && ch === '"') interp = 'php';
    else if (lang === 'ruby' && ch === '"') interp = 'ruby';
    let j = i + q.length;
    let segStart = j;
    while (j < n) {
      if (text[j] === '\\') { j += 2; continue; }
      if (text.startsWith(q, j)) break;
      if (!triple && ch !== '`' && text[j] === '\n' && lang !== 'php' && lang !== 'ruby') break;
      const open = (interp === 'js' && text.startsWith('${', j)) ? 2 : (interp === 'brace' && text[j] === '{' && text[j + 1] !== '{') ? 1 : (interp === 'ruby' && text.startsWith('#{', j)) ? 2 : (interp === 'php' && text.startsWith('{$', j)) ? 1 : 0;
      if (open) {
        blank(segStart, j);
        let depth = 1, k = j + open;
        while (k < n && depth) { if (text[k] === '{') depth++; else if (text[k] === '}') depth--; k++; }
        j = k; segStart = j; continue;
      }
      if (interp === 'php' && text[j] === '$' && /[A-Za-z_]/.test(text[j + 1] || '')) {
        blank(segStart, j);
        let k = j + 1; while (k < n && /[\w\[\]'>-]/.test(text[k]) && !text.startsWith(q, k)) k++;
        j = k; segStart = j; continue;
      }
      j++;
    }
    blank(segStart, Math.min(j, n));
    i = Math.min(j + q.length, n);
  }
  return out.join('');
}

function statementEnd(maskedText) {
  let depth = 0;
  for (let k = 0; k < maskedText.length; k++) {
    const c = maskedText[k];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (depth === 0) return k; depth--; }
    else if (c === ';' && depth === 0) return k;
  }
  return -1;
}

function identRegex(name) {
  return new RegExp(`(?<![\\w$])${escapeRegExp(name)}(?![\\w$])`);
}

// Returns { tainted: Map<name, sourceLine>, sourceRe, hasTaint(line) }
function analyzeTaint(codeLines, lang, options = {}) {
  const sourceRe = SOURCES[lang];
  const assigns = ASSIGN[lang];
  const tainted = new Map();
  if (!sourceRe || !assigns) return { tainted, sourceRe, lineTainted: () => null };

  for (const n of frameworkParamSources(codeLines, lang)) tainted.set(n, 0);
  // Express-style handler parameters: (req, res) => — `req` is already a source via SOURCES.

  // Fold multi-line destructuring (`const {\n a,\n b\n} = req.body`) into one logical line.
  const logical = codeLines.slice();
  if (lang === 'javascript' || lang === 'typescript') {
    for (let i = 0; i < logical.length; i++) {
      if (!/\b(?:const|let|var)\s*[{[][^}\]]*$/.test(logical[i])) continue;
      let j = i, joined = logical[i];
      while (j + 1 < logical.length && j - i < 15 && !/[}\]]\s*=/.test(joined)) { j++; joined += ' ' + logical[j].trim(); }
      if (/[}\]]\s*=/.test(joined)) { logical[i] = joined; for (let k = i + 1; k <= j; k++) logical[k] = ''; i = j; }
    }
  }
  const parsed = [];
  for (let i = 0; i < logical.length; i++) {
    const orig = logical[i];
    if (orig.length > 2000) continue;
    const line = maskStrings(orig, lang);
    for (const a of assigns) {
      const m = line.match(a.re);
      if (!m) continue;
      let lhs = a.swap ? m[2] : m[1];
      // RHS from the original text (same offsets) so sources like request.args["x"] stay visible.
      const rhsMasked = a.swap ? m[1] : m[2];
      const rhsStart = line.indexOf(rhsMasked, m.index);
      let rhs = orig.slice(rhsStart, rhsStart + rhsMasked.length);
      // Stop at the end of the statement so `a = SAFE[x]; b = use(a)` on one line is parsed correctly.
      const semi = statementEnd(line.slice(rhsStart, rhsStart + rhsMasked.length));
      if (semi >= 0) rhs = rhs.slice(0, semi);
      let names;
      if (a.destructure) {
        names = lhs.split(',').map((p) => p.split(':').pop().split('=')[0].replace(/\.\.\./, '').trim()).filter(Boolean);
      } else if (a.multi) {
        names = lhs.split(',').map((s) => s.trim()).filter(Boolean);
      } else {
        names = [lhs.trim()];
      }
      parsed.push({ i, names, rhs });
      break;
    }
  }

  // Fixpoint propagation (bounded).
  for (let iter = 0; iter < 6; iter++) {
    let changed = false;
    for (const { i, names, rhs } of parsed) {
      if (KILLERS.test(rhs) && !/[+`]|\$\{|%|\.format\(|f["']/.test(rhs.replace(KILLERS, ''))) continue;
      if (options.genericSanitizers !== false && SANITIZERS.test(rhs) &&
          !(options.rejectHtmlSanitizers && /\b(?:forHtml|forHtmlContent|encodeForHTML|htmlEscape|escapeHtml|escapeHtml4)\s*\(/.test(rhs))) continue;
      if (lang === 'php' && /\$_FILES\s*\[[^\]]+\]\s*\[\s*['"](?:tmp_name|size|error)['"]\s*\]/.test(rhs) && !/['"]name['"]/.test(rhs)) continue; // server-generated
      // Lookup in a constant allow-list table: ROUTES[req.query.x] → value comes from the table.
      if (/^\s*(?:await\s+)?\$?[A-Z][A-Z0-9_]{2,}(?:\s*\[.+\]|\.(?:get|getOrDefault|fetch)\s*\(.+\))\s*(?:(?:\?\?|\|\||\bor\b).*)?;?\s*$/.test(rhs)) continue;
      let hit = sourceRe.test(rhs);
      if (!hit) for (const t of tainted.keys()) { if (identRegex(t).test(rhs)) { hit = true; break; } }
      if (!hit) continue;
      for (const nm of names) {
        if (!nm || /^(?:req|request|res|response|ctx|self|this|_)$/.test(nm)) continue;
        if (!tainted.has(nm)) { tainted.set(nm, i + 1); changed = true; }
      }
    }
    if (!changed) break;
  }

  const cache = new Map();
  for (const t of tainted.keys()) cache.set(t, identRegex(t));
  const memo = new Map();
  function lineTainted(text) {
    if (memo.has(text)) return memo.get(text);
    const r = computeTainted(text);
    if (memo.size < 20000) memo.set(text, r);
    return r;
  }
  function computeTainted(text) {
    const masked = maskStrings(text, lang);
    const m = masked.match(sourceRe);
    if (m) return { kind: 'source', name: text.slice(m.index, m.index + m[0].length) };
    for (const [t, re] of cache) if (re.test(masked)) return { kind: 'var', name: t, from: tainted.get(t) };
    return null;
  }
  return { tainted, sourceRe, lineTainted };
}

module.exports = { detectLanguage, stripComments, analyzeTaint, maskStrings, SOURCES, KILLERS, SANITIZERS };
