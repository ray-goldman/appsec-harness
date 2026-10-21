'use strict';

// Bounded XML subset, not an XML processor. No entities, DTDs, namespaces,
// transforms or external resources are resolved. Unsupported documents yield
// no findings; these checks never suppress findings from other rules.
function elements(raw) {
  if (raw.length > 1024 * 1024 || /<!DOCTYPE|<!ENTITY|[\x00-\x08\x0b\x0c\x0e-\x1f]/i.test(raw)) return [];
  const stack = [], attributeStack = [], out = [];
  let i = 0, line = 1, col = 1, rootSeen = false;
  function advance(end) {
    for (; i < end; i++) { if (raw[i] === '\n') { line++; col = 1; } else col++; }
  }
  while (i < raw.length) {
    if (/\s/.test(raw[i])) { advance(i + 1); continue; }
    if (raw.startsWith('<!--', i) || raw.startsWith('<![CDATA[', i)) {
      const comment = raw.startsWith('<!--', i), close = comment ? '-->' : ']]>';
      const end = raw.indexOf(close, i + (comment ? 4 : 9));
      if (end < 0 || (!comment && !stack.length)) return [];
      if (comment && /--|-$/.test(raw.slice(i + 4, end))) return [];
      advance(end + close.length); continue;
    }
    if (raw.startsWith('<?xml ', i) && !rootSeen && out.length === 0) {
      const end = raw.indexOf('?>', i + 6);
      if (end < 0 || end - i > 1024) return [];
      if (!(i === 0 || i === 1 && raw[0] === '\uFEFF') || !/^<\?xml\s+version=(?:"1\.0"|'1\.0')(?:\s+encoding=(?:"[A-Za-z][\w.-]*"|'[A-Za-z][\w.-]*'))?(?:\s+standalone=(?:"(?:yes|no)"|'(?:yes|no)'))?\s*\?>$/.test(raw.slice(i, end + 2))) return [];
      advance(end + 2); continue;
    }
    if (raw[i] !== '<') {
      if (!stack.length) return [];
      const end = raw.indexOf('<', i);
      if (end < 0) return [];
      // Text-bearing configuration sections are outside this bounded subset.
      if (raw.slice(i, end).trim()) return [];
      advance(end); continue;
    }
    let end = i + 1, quote = null;
    for (; end < raw.length && end - i <= 8192; end++) {
      const ch = raw[end];
      if (quote) { if (ch === quote) quote = null; }
      else if (ch === '"' || ch === "'") quote = ch;
      else if (ch === '>') break;
      else if (ch === '<') return [];
    }
    if (end >= raw.length || end - i > 8192 || quote) return [];
    const tag = raw.slice(i + 1, end);
    if (tag[0] === '/') {
      const close = tag.match(/^\/([A-Za-z_][\w.-]*)\s*$/);
      if (!close || stack.pop() !== close[1]) return [];
      attributeStack.pop();
    } else {
      const name = tag.match(/^([A-Za-z_][\w.-]*)(?=\s|\/|$)/);
      if (!name || stack.length >= 64 || out.length >= 10000) return [];
      if (!stack.length) { if (rootSeen || name[1] !== 'configuration') return []; rootSeen = true; }
      const attrs = Object.create(null);
      let rest = tag.slice(name[0].length), count = 0;
      while (rest.trim() && rest.trim() !== '/') {
        const attr = rest.match(/^\s+([A-Za-z_][\w.-]*)\s*=\s*(["'])([^]*?)\2/);
        if (!attr || ++count > 64 || attr[1] === 'xmlns' || Object.hasOwn(attrs, attr[1]) || /[<&]/.test(attr[3])) return [];
        attrs[attr[1]] = attr[3]; rest = rest.slice(attr[0].length);
      }
      if (rest.trim() === '/' && !tag.endsWith('/')) return [];
      out.push({ path: [...stack, name[1]].join('/'), attrs, parentAttrs: attributeStack.at(-1), line, col });
      if (rest.trim() !== '/') { stack.push(name[1]); attributeStack.push(attrs); }
    }
    advance(end + 1);
  }
  return rootSeen && !stack.length ? out : [];
}

const cache = new Map();
function configHits(raw, rule) {
  if (raw.length > 1024 * 1024) return [];
  // All five rules share one bounded document cache, replaced for the next file.
  if (!cache.has(raw)) { cache.clear(); cache.set(raw, elements(raw)); }
  return cache.get(raw).filter(e => {
    const { path: p, attrs: a } = e;
    if (rule === 'debug') return (p === 'configuration/system.web/compilation' && a.debug === 'true') ||
      (p === 'configuration/system.web/trace' && a.enabled === 'true' && a.localOnly === 'false');
    if (rule === 'errors') return (p === 'configuration/system.web/customErrors' && a.mode === 'Off') ||
      (p === 'configuration/system.webServer/httpErrors' && a.errorMode === 'Detailed') ||
      (p === 'configuration/system.serviceModel/behaviors/serviceBehaviors/behavior/serviceDebug' && a.includeExceptionDetailInFaults === 'true');
    if (rule === 'cookies') return p === 'configuration/system.web/httpCookies' && (a.httpOnlyCookies === 'false' || a.requireSSL === 'false');
    if (rule === 'forms') return (p === 'configuration/system.web/authentication/forms' && e.parentAttrs?.mode === 'Forms' &&
      (a.requireSSL === 'false' || ['UseUri', 'AutoDetect', 'UseDeviceProfile'].includes(a.cookieless))) ||
      (p === 'configuration/system.web/sessionState' && ['true', 'UseUri', 'AutoDetect', 'UseDeviceProfile'].includes(a.cookieless));
    if (rule === 'wcf') return /^configuration\/system\.serviceModel\/bindings\/(?:basicHttpBinding|wsHttpBinding|netTcpBinding|netNamedPipeBinding)\/binding\/security$/.test(p) && a.mode === 'None';
    return false;
  }).map(({ line, col }) => ({ line, col }));
}
module.exports = { configHits };
