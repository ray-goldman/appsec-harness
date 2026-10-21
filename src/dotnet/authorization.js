'use strict';

function balancedEnd(text, open) {
  let depth = 0, quote = null, verbatim = false;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (!verbatim && c === '\\') { i++; continue; }
      if (verbatim && c === '"' && text[i + 1] === '"') { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; verbatim = c === '"' && text[i - 1] === '@'; continue; }
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
  }
  return -1;
}

function buildDotnetRoutes(files) {
  const routes = [];
  for (const { file, source } of files || []) {
    if (typeof source !== 'string' || !file) continue;
    const groups = new Map();
    for (const m of source.matchAll(/\b(?:var|IEndpointRouteBuilder)\s+(\w+)\s*=\s*\w+\.MapGroup\s*\(\s*(["'])([^"']*)\2\s*\)\s*([^;]*);/g)) {
      groups.set(m[1], { path: m[3], authorized: /\.RequireAuthorization\s*\(/.test(m[4]) });
    }
    const masked = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|@?"(?:""|\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, m => ' '.repeat(m.length));
    const classRe = /((?:\s*\[[^\]]+\]\s*)*)(?:(?:public|internal|abstract|partial|sealed)\s+)*class\s+(\w+)([^{};]{0,500})\{/g;
    for (let cm; (cm = classRe.exec(masked));) {
      const open = classRe.lastIndex - 1, end = balancedEnd(masked, open);
      if (end < 0 || !(/Controller\b/.test(cm[2]) || /:\s*[^\n{]*\bController(?:Base)?\b/.test(cm[3]))) continue;
      const classAuth = /\[\s*Authorize(?:Attribute)?\b/.test(cm[1]);
      const body = source.slice(open + 1, end), baseOffset = open + 1;
      const actionRe = /((?:\s*\[[^\]]+\]\s*)+)(?:(?:public|protected|internal|virtual|override|async|static|new)\s+)+[\w<>,.?\[\]]+\s+(\w+)\s*\([^(){};]{0,1000}\)\s*\{/g;
      for (let am; (am = actionRe.exec(body));) {
        const http = am[1].match(/\[\s*Http(Get|Post|Put|Patch|Delete|Head|Options)(?:Attribute)?(?:\s*\(\s*"([^"]*)")?/i);
        if (!http) continue;
        const anonymous = /\[\s*AllowAnonymous(?:Attribute)?\b/.test(am[1]);
        routes.push({ routeId: `${file}#${am[2]}`, file, framework: 'mvc', controller: cm[2], action: am[2],
          verb: http[1].toUpperCase(), path: http[2] || null, sourceSpan: { start: baseOffset + am.index, end: baseOffset + actionRe.lastIndex },
          authEvidence: { classAuthorize: classAuth, actionAuthorize: /\[\s*Authorize(?:Attribute)?\b/.test(am[1]), allowAnonymous: anonymous },
          effectivePolicy: anonymous ? false : classAuth || /\[\s*Authorize(?:Attribute)?\b/.test(am[1]), objectLevelChecks: [], unresolvedPolicyReasons: [] });
      }
      classRe.lastIndex = end + 1;
    }
    const endpointRe = /\b([\w.]+)\.(MapGet|MapPost|MapPut|MapPatch|MapDelete|MapMethods)\s*\(\s*(["'])([^"']+)\3/g;
    for (let em; (em = endpointRe.exec(source));) {
      const receiver = em[1].split('.').at(-1), group = groups.get(receiver);
      const statementEnd = source.indexOf(';', endpointRe.lastIndex);
      const tail = source.slice(endpointRe.lastIndex, statementEnd < 0 ? Math.min(source.length, endpointRe.lastIndex + 500) : statementEnd);
      const anonymous = /^\s*\.AllowAnonymous\s*\(/.test(tail);
      const explicitAuth = /^\s*\.RequireAuthorization\s*\(/.test(tail);
      const path = `${group?.path || ''}${em[4]}` || '/';
      const verb = em[2] === 'MapMethods' ? null : em[2].slice(3).toUpperCase();
      routes.push({ routeId: `${file}@${em.index}`, file, framework: 'minimal-api', controller: null, action: null, verb, path,
        sourceSpan: { start: em.index, end: endpointRe.lastIndex },
        authEvidence: { groupRequireAuthorization: !!group?.authorized, endpointRequireAuthorization: explicitAuth, allowAnonymous: anonymous },
        effectivePolicy: anonymous ? false : !!(group?.authorized || explicitAuth), objectLevelChecks: [],
        unresolvedPolicyReasons: em[2] === 'MapMethods' ? ['method-list-not-resolved'] : [] });
    }
  }
  return routes;
}

function middlewareOrder(source) {
  if (typeof source !== 'string' || /#if\b|if\s*\(/.test(source)) return { status: 'unresolved', authenticationIndex: null, authorizationIndex: null };
  const clean = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|@?"(?:""|\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, m => ' '.repeat(m.length));
  const authn = clean.indexOf('UseAuthentication('), authz = clean.indexOf('UseAuthorization(');
  if (authn < 0 || authz < 0) return { status: 'not-visible', authenticationIndex: authn < 0 ? null : authn, authorizationIndex: authz < 0 ? null : authz };
  return { status: authn < authz ? 'ordered' : 'misordered', authenticationIndex: authn, authorizationIndex: authz };
}

module.exports = { buildDotnetRoutes, middlewareOrder };
