'use strict';
// Repository-wide checks that need more than one file of context.
const { authLoggingEvidence } = require('../auth-logging-evidence');

module.exports = [
  {
    id: 'PROJ-HEADERS-001', title: 'Express app without security headers middleware (helmet)',
    owasp: 'A02', cwe: [693, 1021], severity: 'low', confidence: 'medium',
    check: (ctx) => {
      const app = ctx.files.find((f) => /\bexpress\s*\(\s*\)/.test(f.code) && /\.listen\s*\(|module\.exports|export default/.test(f.code));
      if (!app) return [];
      if (ctx.allCode.some((c) => /\bhelmet\b|Content-Security-Policy|X-Frame-Options|frameguard/i.test(c))) return [];
      return [{ file: app.rel, line: app.code.split('\n').findIndex((l) => /\bexpress\s*\(\s*\)/.test(l)) + 1 }];
    },
    message: 'No CSP, frame-ancestors, HSTS, or nosniff headers are set — XSS impact and clickjacking are not mitigated.',
    fix: '`app.use(helmet())` and define a Content-Security-Policy.',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
  },
  {
    id: 'PROJ-RATELIMIT-001', title: 'Login endpoint with no rate limiting / lockout library',
    owasp: 'A07', cwe: [307], severity: 'medium', confidence: 'low',
    check: (ctx) => {
      const login = ctx.routes.find((r) => /log[-_]?in|sign[-_]?in|auth(?:enticate)?\b|token$/i.test(r.path) && /POST|ANY/.test(r.method));
      if (!login) return [];
      const libs = /express-rate-limit|rate-limiter-flexible|express-brute|@fastify\/rate-limit|express-slow-down|slowapi|flask[-_]limiter|django[-_]ratelimit|django-axes|bucket4j|resilience4j|RateLimiter|rack-attack|throttle|limiter|lockout|max_?attempts|failed_?attempts|login_?attempts/i;
      if (ctx.allCode.some((c) => libs.test(c)) || ctx.manifests.filter((m) => !m.lock).some((m) => libs.test(m.raw))) return [];
      return [{ file: login.file, line: login.line, detail: `${login.method} ${login.path}` }];
    },
    message: 'Without throttling or lockout, credential stuffing and password spraying run unhindered.',
    fix: 'Add per-account and per-IP throttling with backoff; alert on spikes; support MFA.',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks'],
  },
  {
    id: 'PROJ-CSRF-001', title: 'Cookie-session app with state-changing routes and no CSRF defence',
    owasp: 'A01', cwe: [352], severity: 'medium', confidence: 'low',
    check: (ctx) => {
      const sess = ctx.files.find((f) => /require\(\s*['"](?:express-session|cookie-session)['"]\)|from\s+['"](?:express-session|cookie-session)['"]/.test(f.code));
      if (!sess) return [];
      if (!ctx.routes.some((r) => /POST|PUT|PATCH|DELETE/.test(r.method))) return [];
      if (ctx.allCode.some((c) => /\bcsurf\b|csrf-csrf|csrf-sync|lusca|_csrf|csrfToken|sameSite\s*:\s*['"](?:strict|lax)['"]/i.test(c))) return [];
      return [{ file: sess.rel, line: 1 }];
    },
    message: 'Session cookies are sent on cross-site requests; without CSRF tokens or SameSite=Lax/Strict, attacker pages can submit forms as the victim.',
    fix: 'Set `cookie: { sameSite: "lax" }` and use a CSRF token library (csrf-csrf / csrf-sync).',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'PROJ-LOGGING-001', title: 'Authentication code with no security event logging',
    owasp: 'A09', cwe: [778, 223], severity: 'low', confidence: 'low',
    check: (ctx) => {
      const hint = /\b(?:login|authenticate|signIn|verifyPassword|password_verify|check_password|bcrypt\.compare|compare_digest)\b/;
      const authFiles = ctx.files.filter((f) => hint.test(f.code)).map((f) => ({ ...f, ...authLoggingEvidence(f) })).filter((f) => hint.test(f.authCode));
      if (!authFiles.length) return [];
      const logs = /\b(?:logger|log|logging|winston|pino|bunyan|console)\.(?:warn|error|info|warning|critical|audit)\b|audit[_-]?log|securityLog|Log\.(?:w|e|i)\(|slog\.|zap\.|logrus\./;
      return authFiles.filter((f) => !logs.test(f.loggingCode)).slice(0, 5).map((f) => ({ file: f.rel, line: f.code.split('\n').findIndex((l) => /login|authenticate|signIn|password/i.test(l)) + 1 || 1 }));
    },
    message: 'Login failures, lockouts and privilege changes are not logged here, so brute force and account takeover go unnoticed.',
    fix: 'Log auth successes/failures (user id, source IP, outcome — never passwords) to a monitored sink and alert on anomalies.',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#which-events-to-log'],
  },
  ...[
    ['sql','A05',[89],'high'], ['command','A05',[78],'high'], ['ssrf','A01',[918],'high'],
    ['path','A01',[22],'high'], ['xss','A05',[79],'medium'],
  ].map(([category,owasp,cwe,severity]) => ({
    id: 'DOTNET-PROJECT-TAINT-'+category.toUpperCase(),
    title: 'Request data reaches a '+category+' sink across project calls',
    owasp, cwe, severity, confidence: 'high', check: () => [],
    message: 'Request data reaches a supported sink through resolved C# project calls. Review the source, every call edge, and sink context.',
    fix: 'Validate or encode the value for the sink context, or use a structured API that separates data from commands.',
    refs: ['https://owasp.org/www-project-top-ten/'],
  })),
];
