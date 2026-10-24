'use strict';
// Source files only. Report/output directories have a separate operator-selected
// boundary. Portable path checks are not an atomic directory-handle sandbox;
// use stable snapshots when another process can mutate an audited tree.
const fs = require('fs');
const path = require('path');
const MAX_SOURCE_BYTES = 1024 * 1024;
const invalid = () => new Error('Source file must be a regular relative file inside the target root, without symlinks or junctions.');
const samePath = (a, b) => path.relative(a, b) === '';
const sameIdentity = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sameFile = (a, b) => sameIdentity(a, b) && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
function inside(root, file) {
  const relative = path.relative(root, file);
  return relative !== '' && !path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep);
}

function snapshot(root, relative) {
  if (typeof root !== 'string' || typeof relative !== 'string' || !relative || relative.includes('\0') ||
      path.isAbsolute(relative) || path.win32.isAbsolute(relative) || /^[A-Za-z]:/.test(relative) ||
      relative.split(/[\\/]/).includes('..') || process.platform === 'win32' && relative.includes(':')) throw invalid();
  const base = fs.realpathSync(root);
  const rootStat = fs.lstatSync(base, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw invalid();
  const candidate = path.resolve(base, relative);
  if (!inside(base, candidate)) throw invalid();
  const parts = path.relative(base, candidate).split(path.sep);
  if (parts.length > 40) throw invalid();
  const entries = [{ file: base, stat: rootStat }];
  let current = base;
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    const stat = fs.lstatSync(current, { bigint: true });
    if (stat.isSymbolicLink() || (i === parts.length - 1 ? !stat.isFile() : !stat.isDirectory())) throw invalid();
    const canonical = fs.realpathSync(current);
    if (!inside(base, canonical) || !samePath(current, canonical)) throw invalid();
    entries.push({ file: canonical, stat });
    current = canonical;
  }
  const file = entries.at(-1);
  if (file.stat.size > BigInt(MAX_SOURCE_BYTES)) throw invalid();
  return { base, entries, file };
}

function unchanged(before, after) {
  return samePath(before.base, after.base) && before.entries.length === after.entries.length &&
    before.entries.every((entry, i) => samePath(entry.file, after.entries[i].file) && sameIdentity(entry.stat, after.entries[i].stat)) &&
    sameFile(before.file.stat, after.file.stat);
}

function readConfinedText(root, relative) {
  let fd;
  try {
    const before = snapshot(root, relative);
    // O_NONBLOCK prevents an observed regular file swapped for a FIFO from
    // blocking open; O_NOFOLLOW additionally protects the leaf where supported.
    fd = fs.openSync(before.file.file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || !sameFile(before.file.stat, opened) || !unchanged(before, snapshot(root, relative))) throw invalid();
    // An extra byte detects growth without following readFileSync's unbounded
    // file-growth loop. Content and path changes are checked before returning.
    const buffer = Buffer.alloc(Number(opened.size) + 1);
    let size = 0;
    while (size < buffer.length) {
      const count = fs.readSync(fd, buffer, size, buffer.length - size, size);
      if (!count) break;
      size += count;
    }
    if (BigInt(size) !== opened.size || !sameFile(opened, fs.fstatSync(fd, { bigint: true })) ||
        !unchanged(before, snapshot(root, relative))) throw invalid();
    return buffer.subarray(0, size).toString('utf8');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

module.exports = { readConfinedText, MAX_SOURCE_BYTES };
