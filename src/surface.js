'use strict';
// Attack-surface map: HTTP entry points + visible auth guards. Feeds A01 (Broken Access Control)
// triage, which pattern rules cannot decide on their own.

const AUTH_HINT = /\b(?:auth\w*|authenticate\w*|requireAuth|isAuthenticated|ensureAuth\w*|ensureLoggedIn|passport\.authenticate|verify(?:Token|JWT|Session|User)\w*|jwtCheck|checkJwt|requireLogin|isLoggedIn|loggedIn|requireUser|isAdmin|requireAdmin|requireRole|hasRole|authorize\w*|guard\w*|withAuth|loginRequired|login_required|jwt_required|permission_required|roles_required|staff_member_required|user_passes_test|PreAuthorize|Secured|RolesAllowed|before_action\s+:authenticate\w*|authenticate_user!|getServerSession|currentUser|clerk|withApiAuth|protect\w*|acl|can\(|permit\w*|apiKey\w*|requireApiKey|basicAuth|bearer\w*)\b/i;

const PUBLIC_PATH = /(?:^|\/)(?:log[-_]?in|sign[-_]?(?:in|up)|register|auth|oauth\d?|callback|webhooks?|health\w*|ready\w*|live\w*|status|metrics|logout|forgot[-_]?password|reset[-_]?password|password[-_]?reset|verify[-_]?email|csp[-_]?report|public|static|assets|favicon\.ico|robots\.txt|\.well-known)(?:\/|$)/i;

function extractRoutes(rel, lang, codeLines, raw) {
  const routes = [];
  const add = (r) => routes.push({ file: rel, ...r });

  if (lang === 'javascript' || lang === 'typescript') {
    let globalAuthLine = 0;
    codeLines.forEach((l, i) => {
      if (/\b(?:app|router|server|api)\.use\s*\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?[^)]*/.test(l) && AUTH_HINT.test(l)) globalAuthLine = globalAuthLine || i + 1;
      const m = l.match(/\b(?:app|router|server|api|r|routes|fastify|hono|instance)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]+)\2\s*(,[^\n]*)?/i);
      if (!m) return;
      const mw = m[4] || '';
      let auth = AUTH_HINT.test(mw) ? 'route' : (globalAuthLine && globalAuthLine < i + 1 ? 'global' : 'none');
      add({ line: i + 1, method: m[1].toUpperCase(), path: m[3], auth, framework: 'express-like' });
    });
    // Next.js app router / pages api
    const nextApp = rel.match(/(?:^|\/)app\/(.*)\/route\.[jt]sx?$/);
    const nextPages = rel.match(/(?:^|\/)pages\/api\/(.*)\.[jt]sx?$/);
    if (nextApp || nextPages) {
      const p = '/' + (nextApp ? nextApp[1] : 'api/' + nextPages[1]).replace(/\/index$/, '').replace(/\(([^)]+)\)\//g, '');
      const fileAuth = AUTH_HINT.test(raw) ? 'route' : 'none';
      const methods = nextApp ? [...raw.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/g)].map((x) => x[1]) : ['ANY'];
      const lineOf = (name) => Math.max(1, codeLines.findIndex((l) => new RegExp(`export\\s+(?:async\\s+)?(?:function|const)\\s+${name}\\b`).test(l)) + 1);
      for (const meth of methods.length ? methods : ['ANY']) add({ line: meth === 'ANY' ? 1 : lineOf(meth), method: meth, path: p, auth: fileAuth, framework: 'nextjs' });
    }
    // Next.js server actions
    if (/^\s*['"]use server['"]/m.test(raw)) {
      codeLines.forEach((l, i) => {
        const m = l.match(/export\s+async\s+function\s+(\w+)/);
        if (m) add({ line: i + 1, method: 'ACTION', path: `server-action:${m[1]}`, auth: AUTH_HINT.test(codeLines.slice(i, i + 12).join('\n')) ? 'route' : 'none', framework: 'nextjs' });
      });
    }
  }

  if (lang === 'python') {
    codeLines.forEach((l, i) => {
      const m = l.match(/@\w+(?:\.\w+)*\.(route|get|post|put|patch|delete|api_route)\s*\(\s*['"]([^'"]+)['"]([^)]*)\)/);
      if (!m) return;
      let methods = m[1] === 'route' || m[1] === 'api_route' ? ((m[3].match(/methods\s*=\s*\[([^\]]+)\]/) || [])[1] || "'GET'").replace(/['"\s]/g, '').split(',') : [m[1].toUpperCase()];
      const block = codeLines.slice(Math.max(0, i - 4), i + 6).join('\n');
      const auth = AUTH_HINT.test(block) || /Depends\s*\([^)]*(?:user|auth|token|security)/i.test(block) ? 'route' : 'none';
      for (const meth of methods) add({ line: i + 1, method: meth.toUpperCase(), path: m[2], auth, framework: 'flask/fastapi' });
    });
    if (/urls\.py$/.test(rel)) codeLines.forEach((l, i) => {
      const m = l.match(/\b(?:re_)?path\s*\(\s*r?['"]([^'"]*)['"]\s*,\s*([\w.]+)/);
      if (m) add({ line: i + 1, method: 'ANY', path: '/' + m[1], auth: /login_required|permission_required|staff_member_required/.test(l) ? 'route' : 'unknown', framework: 'django', handler: m[2] });
    });
  }

  if (lang === 'java' || lang === 'kotlin') {
    let classBase = '';
    let classAuth = false;
    codeLines.forEach((l, i) => {
      const cm = l.match(/@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?["']([^"']+)["']\s*\)\s*$/);
      if (cm && /\bclass\b/.test(codeLines.slice(i, i + 4).join(' '))) { classBase = cm[1]; classAuth = AUTH_HINT.test(codeLines.slice(Math.max(0, i - 4), i + 1).join('\n')); return; }
      const m = l.match(/@(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*["']([^"']*)["'][^)]*\))?/);
      if (!m) return;
      const block = codeLines.slice(Math.max(0, i - 4), i + 2).join('\n');
      add({ line: i + 1, method: m[1] === 'Request' ? 'ANY' : m[1].toUpperCase(), path: (classBase + (m[2] || '')).replace(/\/\//g, '/') || '/', auth: classAuth || AUTH_HINT.test(block) ? 'route' : 'unknown', framework: 'spring' });
    });
  }

  if (lang === 'go') {
    codeLines.forEach((l, i) => {
      let m = l.match(/\b(?:http|mux|r|router|e|g|api|v\d)\.(?:HandleFunc|Handle)\s*\(\s*"(?:(GET|POST|PUT|PATCH|DELETE)\s+)?([^"]+)"\s*,\s*([^\n]*)/);
      if (m) { add({ line: i + 1, method: m[1] || 'ANY', path: m[2], auth: AUTH_HINT.test(m[3]) ? 'route' : 'none', framework: 'net/http' }); return; }
      m = l.match(/\b(?:r|router|e|g|api|app|v\d|group)\.(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*"([^"]+)"\s*,\s*([^\n]*)/);
      if (m) add({ line: i + 1, method: m[1].toUpperCase(), path: m[2], auth: AUTH_HINT.test(m[3]) ? 'route' : 'none', framework: 'gin/echo/chi' });
    });
  }

  if (lang === 'php' && /\$_(?:GET|POST|REQUEST|FILES)\b/.test(raw)) {
    const auth = /\$_SESSION\s*\[\s*['"](?:user|uid|logged|auth|admin|id)\w*['"]\s*\]|is_logged_in|require_login|check_auth|Auth::|auth\(\)|current_user_can|wp_verify_nonce/i.test(raw) ? 'route' : 'none';
    const post = /\$_(?:POST|FILES)\b|REQUEST_METHOD['"]\]\s*===?\s*['"]POST/.test(raw);
    add({ line: 1, method: post ? 'POST' : 'GET', path: '/' + rel, auth, framework: 'php-script' });
  }

  if (lang === 'ruby' && /routes\.rb$/.test(rel)) {
    codeLines.forEach((l, i) => {
      const m = l.match(/^\s*(get|post|put|patch|delete|resources?|match)\s+['":]?([\w\/:.-]+)/);
      if (m) add({ line: i + 1, method: /resources?/.test(m[1]) ? 'CRUD' : m[1].toUpperCase(), path: m[2], auth: 'unknown', framework: 'rails' });
    });
  }
  return routes;
}

function routeFindings(routes) {
  const out = [];
  for (const r of routes) {
    if (r.auth !== 'none') continue;
    const changing = /^(?:POST|PUT|PATCH|DELETE|ACTION|ANY|CRUD)$/.test(r.method);
    const admin = /(?:^|\/)(?:admin|internal|debug|manage(?:ment)?|actuator|console|backup|export|config|settings|users?\/\:?\w*\/(?:role|permissions?))(?:\/|$)/i.test(r.path);
    if (PUBLIC_PATH.test(r.path) && !admin) continue;
    if (!changing && !admin) continue;
    out.push({
      ruleId: 'AUTHZ-ROUTE-001', file: r.file, line: r.line, source: 'surface',
      severity: admin ? 'high' : 'medium', confidence: 'low',
      title: `${admin ? 'Privileged' : 'State-changing'} route without a visible auth guard: ${r.method} ${r.path}`,
      detail: `${r.framework}: ${r.method} ${r.path}`,
    });
  }
  return out;
}

module.exports = { extractRoutes, routeFindings, AUTH_HINT };
