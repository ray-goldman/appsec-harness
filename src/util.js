'use strict';
const crypto = require('crypto');

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CONFIDENCE_RANK = { low: 1, medium: 2, high: 3 };

function sevRank(s) { return SEVERITY_RANK[s] ?? 0; }
function confRank(c) { return CONFIDENCE_RANK[c] ?? 1; }

function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// Build an offset->line lookup for a text blob.
function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}
function offsetToLine(starts, off) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= off) lo = mid; else hi = mid - 1;
  }
  return { line: lo + 1, col: off - starts[lo] + 1 };
}

// Never print full secrets into reports.
function redact(s) {
  if (!s) return s;
  if (s.length <= 8) return s[0] + '*'.repeat(s.length - 1);
  return s.slice(0, 4) + '*'.repeat(Math.min(s.length - 6, 24)) + s.slice(-2);
}

function shannonEntropy(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

function isProbablyBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

// ---- Lenient version comparison (npm semver, PEP 440-ish, Maven, Go, RubyGems) ----
function parseVersion(v) {
  if (v == null) return null;
  let s = String(v).trim().replace(/^v/i, '').replace(/^[=\s]+/, '');
  s = s.split('+')[0]; // drop build metadata
  const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/);
  if (!m) return null;
  const nums = m[1].split('.').map(Number);
  let pre = m[2].replace(/^[-._]/, '').toLowerCase();
  // Maven / PEP440 qualifiers that mean "release"
  if (['final', 'release', 'ga', 'redhat', ''].includes(pre)) pre = '';
  if (/^(sp|post|p)\d*/.test(pre)) pre = ''; // service packs / post-releases sort as release
  return { nums, pre };
}

function cmpPre(a, b) {
  if (a === b) return 0;
  if (!a) return 1;   // release > prerelease
  if (!b) return -1;
  const order = (x) => (/^(alpha|a)/.test(x) ? 1 : /^(beta|b)/.test(x) ? 2 : /^(milestone|m)/.test(x) ? 3 : /^(rc|cr)/.test(x) ? 4 : /^(snapshot|dev)/.test(x) ? 0 : 5);
  const oa = order(a), ob = order(b);
  if (oa !== ob) return oa - ob;
  const na = Number((a.match(/(\d+)/) || [0, 0])[1]);
  const nb = Number((b.match(/(\d+)/) || [0, 0])[1]);
  if (na !== nb) return na - nb;
  return a < b ? -1 : 1;
}

function compareVersions(a, b) {
  const pa = typeof a === 'string' ? parseVersion(a) : a;
  const pb = typeof b === 'string' ? parseVersion(b) : b;
  if (!pa || !pb) return NaN;
  const len = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i++) {
    const x = pa.nums[i] || 0, y = pb.nums[i] || 0;
    if (x !== y) return x - y;
  }
  return cmpPre(pa.pre, pb.pre);
}

// range: { introduced?, fixed?, lastAffected?, versions?: [] }
function inRange(version, range) {
  if (range.versions) return range.versions.includes(String(version).replace(/^v/, ''));
  if (range.any) return true;
  const v = parseVersion(version);
  if (!v) return false;
  if (range.introduced && range.introduced !== '0' && compareVersions(v, range.introduced) < 0) return false;
  if (range.fixed && compareVersions(v, range.fixed) >= 0) return false;
  if (range.lastAffected && compareVersions(v, range.lastAffected) > 0) return false;
  return true;
}

// Extract the lowest concrete version a declared range could resolve to (^1.2.3 -> 1.2.3).
function floorOfSpec(spec) {
  if (!spec || typeof spec !== 'string') return null;
  const m = spec.match(/(\d+(?:\.\d+)*(?:[-.][0-9A-Za-z.]+)?)/);
  return m ? m[1] : null;
}

function isTestPath(rel) {
  return /(^|\/)(tests?|__tests__|spec|specs|fixtures?|testdata|mocks?|__mocks__|e2e|cypress|examples?|samples?|docs?)(\/|$)|[._-](test|spec)\.[a-z]+$|_test\.go$|Test\.java$/i.test(rel);
}

function truncate(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }

module.exports = {
  SEVERITY_RANK, CONFIDENCE_RANK, sevRank, confRank, escapeRegExp, sha256, lineStarts, offsetToLine,
  redact, shannonEntropy, isProbablyBinary, parseVersion, compareVersions, inRange, floorOfSpec, isTestPath, truncate,
};
