'use strict';

// Tiny, non-executing Java expression reader. Values are typed and bounded;
// unsupported syntax/types, overflow and exhausted budgets produce unknown.
function tokens(source) {
  if (source.length > 50000) return null;
  const out = [];
  const re = /\s+|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_$][\w$]*|\d[\w.]*|===|!==|>>>|>>|<<|&&|\|\||==|!=|<=|>=|\+\+|--|[+*/%&|^!~<>=?:.,;(){}\[\]-]/gy;
  let pos = 0;
  while (pos < source.length) {
    re.lastIndex = pos;
    const m = re.exec(source);
    if (!m || out.length >= 12000) return null;
    if (!/^\s/.test(m[0])) out.push({ text: m[0], start: pos, end: re.lastIndex });
    pos = re.lastIndex;
  }
  return out;
}
const val = (type, value) => ({ type, value });
const integer = value => Number.isSafeInteger(value) && value >= -2147483648 && value <= 2147483647 ? val('int', value) : null;
const numeric = a => a && (a.type === 'int' || a.type === 'char');
function literal(text) {
  if (/^(true|false)$/.test(text)) return val('boolean', text === 'true');
  if (/^(?:0|[1-9]\d*)$/.test(text)) return integer(Number(text));
  if (!/^["']/.test(text)) return null;
  let value = '';
  const escapes = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', "'": "'", '\\': '\\' };
  for (let i = 1; i < text.length - 1; i++) {
    let c = text[i];
    if (c === '\\') { c = escapes[text[++i]]; if (c === undefined) return null; }
    if (c === '\n' && text[i] !== 'n' || c === '\r' && text[i] !== 'r') return null;
    value += c;
  }
  return text[0] === '"' ? val('String', value) : value.length === 1 ? val('char', value.charCodeAt(0)) : null;
}
const precedence = { '||': 1, '&&': 2, '|': 3, '^': 4, '&': 5, '==': 6, '!=': 6, '<': 7, '>': 7, '<=': 7, '>=': 7, '+': 8, '-': 8, '*': 9, '/': 9, '%': 9 };
function binary(op, a, b) {
  if (!a || !b) return null;
  if (op === '+' && (a.type === 'String' || b.type === 'String')) {
    const string = x => x.type === 'char' ? String.fromCharCode(x.value) : String(x.value);
    const result = string(a) + string(b);
    return result.length <= 4000 ? val('String', result) : null;
  }
  if (op === '==' || op === '!=') {
    if (!(numeric(a) && numeric(b)) && !(a.type === 'boolean' && b.type === 'boolean')) return null;
    return val('boolean', op === '==' ? a.value === b.value : a.value !== b.value);
  }
  if (a.type === 'boolean' && b.type === 'boolean') {
    if (op === '&&' || op === '&') return val('boolean', a.value && b.value);
    if (op === '||' || op === '|') return val('boolean', a.value || b.value);
    if (op === '^') return val('boolean', a.value !== b.value);
    return null;
  }
  if (!numeric(a) || !numeric(b)) return null;
  const x = a.value, y = b.value;
  if (op === '<') return val('boolean', x < y);
  if (op === '>') return val('boolean', x > y);
  if (op === '<=') return val('boolean', x <= y);
  if (op === '>=') return val('boolean', x >= y);
  if (op === '+') return integer(x + y);
  if (op === '-') return integer(x - y);
  if (op === '*') return integer(x * y);
  if (op === '/') return y && !(x === -2147483648 && y === -1) ? integer(Math.trunc(x / y)) : null;
  if (op === '%') return y ? integer(x % y) : null;
  if (op === '&') return integer(x & y);
  if (op === '|') return integer(x | y);
  if (op === '^') return integer(x ^ y);
  return null;
}
function evaluate(source, resolve, budget = { left: 512 }) {
  if (source.length > 4000) return null;
  const ts = tokens(source);
  if (!ts || ts.length > 1024) return null;
  let at = 0;
  function parse(min = 0, depth = 0) {
    if (--budget.left < 0 || depth > 48) throw new Error('budget');
    let node, t = ts[at++];
    if (!t) throw new Error('syntax');
    if (['!', '~', '+', '-'].includes(t.text)) node = { op: 'unary', kind: t.text, child: parse(10, depth + 1) };
    else if (t.text === '(') { node = parse(0, depth + 1); if (ts[at++]?.text !== ')') throw new Error('syntax'); }
    else node = { op: 'atom', text: t.text };
    while (at < ts.length) {
      const op = ts[at].text;
      if (op === '(' || op === '.' || op === '[') {
        // Parse calls/indexes even when unknown so a selected ternary arm can
        // exclude one. Only String.charAt(int) has an evaluated call meaning.
        if (op === '.') { at++; node = { op: 'member', base: node, name: ts[at++]?.text }; continue; }
        at++; const args = [];
        const close = op === '(' ? ')' : ']';
        if (ts[at]?.text !== close) {
          do { args.push(parse(0, depth + 1)); if (ts[at]?.text !== ',') break; at++; } while (true);
        }
        if (ts[at++]?.text !== close) throw new Error('syntax');
        node = { op: op === '(' ? 'call' : 'index', base: node, args }; continue;
      }
      if (op === '?' && min === 0) {
        at++; const yes = parse(0, depth + 1);
        if (ts[at++]?.text !== ':') throw new Error('syntax');
        node = { op: 'ternary', condition: node, yes, no: parse(0, depth + 1) }; continue;
      }
      const p = precedence[op];
      if (!p || p < min) break;
      at++; node = { op, left: node, right: parse(p + 1, depth + 1) };
    }
    return node;
  }
  function run(node, depth = 0) {
    if (--budget.left < 0 || depth > 48) return null;
    if (node.op === 'atom') return literal(node.text) || (/^[A-Za-z_$][\w$]*$/.test(node.text) ? resolve(node.text, budget) : null);
    if (node.op === 'ternary') {
      const c = run(node.condition, depth + 1);
      if (c?.type !== 'boolean') return null;
      const selected = run(c.value ? node.yes : node.no, depth + 1);
      if (numeric(selected)) {
        // Java's conditional numeric type depends on BOTH arms (and whether
        // an int arm is a compile-time constant). Reject mixed/unknown types
        // rather than applying an incorrect char/string conversion later.
        const other = run(c.value ? node.no : node.yes, depth + 1);
        if (!other || other.type !== selected.type) return null;
      }
      return selected;
    }
    if (node.op === 'unary') {
      const a = run(node.child, depth + 1);
      if (node.kind === '!') return a?.type === 'boolean' ? val('boolean', !a.value) : null;
      return numeric(a) ? integer(node.kind === '-' ? -a.value : node.kind === '~' ? ~a.value : a.value) : null;
    }
    if (node.op === 'call') {
      if (node.base.op !== 'member' || node.base.name !== 'charAt' || node.args.length !== 1) return null;
      const a = run(node.base.base, depth + 1), b = run(node.args[0], depth + 1);
      return a?.type === 'String' && numeric(b) && b.value >= 0 && b.value < a.value.length ? val('char', a.value.charCodeAt(b.value)) : null;
    }
    if (node.op === 'member' || node.op === 'index') return null;
    return binary(node.op, run(node.left, depth + 1), run(node.right, depth + 1));
  }
  try { const ast = parse(); return at === ts.length ? run(ast) : null; } catch { return null; }
}

// Parse statement boundaries, including dangling else. Failure disables branch
// pruning for the method. Loops are traversed but never unrolled or executed.
function excludedBranches(source, fact) {
  const ts = tokens(source);
  if (!ts) return [];
  const dead = [], pairs = new Map(), stack = [];
  for (let i = 0; i < ts.length; i++) {
    const t = ts[i].text;
    if (['(', '{', '['].includes(t)) stack.push(i);
    if ([')', '}', ']'].includes(t)) {
      const j = stack.pop();
      if (j === undefined || '({['.indexOf(ts[j].text) !== ')}]'.indexOf(t)) return [];
      pairs.set(j, i);
    }
  }
  if (stack.length) return [];
  let work = 24000;
  const range = (a, b) => { if (a < b) dead.push([ts[a].start, ts[b - 1].end]); };
  const expr = (a, b) => source.slice(ts[a].start, ts[b - 1].end);
  function statement(i, depth = 0) {
    if (--work < 0 || depth > 64 || !ts[i]) throw new Error('budget/syntax');
    const t = ts[i].text;
    if (t === '{') {
      const end = pairs.get(i); if (end === undefined) throw new Error('syntax');
      for (let j = i + 1; j < end;) j = statement(j, depth + 1);
      return end + 1;
    }
    if (t === 'if' || t === 'while' || t === 'for' || t === 'synchronized') {
      if (ts[i + 1]?.text !== '(') throw new Error('syntax');
      const end = pairs.get(i + 1); if (end === undefined) throw new Error('syntax');
      const after = statement(end + 1, depth + 1);
      if (t !== 'if') return after;
      const hasElse = ts[after]?.text === 'else';
      const finish = hasElse ? statement(after + 1, depth + 1) : after;
      const c = fact(expr(i + 2, end), ts[i].start);
      if (c?.type === 'boolean') { if (!c.value) range(end + 1, after); else if (hasElse) range(after + 1, finish); }
      return finish;
    }
    if (t === 'switch') {
      if (ts[i + 1]?.text !== '(') throw new Error('syntax');
      const close = pairs.get(i + 1), begin = close + 1, end = pairs.get(begin);
      if (ts[begin]?.text !== '{' || end === undefined) throw new Error('syntax');
      const labels = [];
      for (let j = begin + 1; j < end;) {
        if (!['case', 'default'].includes(ts[j].text)) throw new Error('switch');
        const label = j++, isDefault = ts[label].text === 'default';
        while (j < end && ts[j].text !== ':') j++;
        if (j === end) throw new Error('switch');
        const value = isDefault ? null : fact(expr(label + 1, j), ts[label].start);
        const start = ++j;
        let finalStatement = -1;
        while (j < end && !['case', 'default'].includes(ts[j].text)) { finalStatement = j; j = statement(j, depth + 1); }
        labels.push({ value, isDefault, start, end: j, finalStatement });
      }
      const selected = fact(expr(i + 2, close), ts[i].start);
      if (!selected || !['int', 'char', 'String'].includes(selected.type) || labels.filter(l => l.isDefault).length > 1) return end + 1;
      if (labels.some(l => !l.isDefault && (!l.value || !(numeric(selected) && numeric(l.value) || selected.type === 'String' && l.value.type === 'String')))) return end + 1;
      // Only direct terminal breaks are modeled. Other control transfers or
      // nested breaks require a fuller CFG, so retain every switch arm.
      for (const l of labels) {
        for (let k = l.start; k < l.end; k++) {
          if (['return', 'throw', 'continue', 'yield', 'switch'].includes(ts[k].text)) return end + 1;
          if (ts[k].text === 'break' && !(k === l.finalStatement && k === l.end - 2 && ts[k + 1].text === ';')) return end + 1;
        }
      }
      let active = labels.findIndex(l => !l.isDefault && l.value.value === selected.value);
      if (active < 0) active = labels.findIndex(l => l.isDefault);
      let running = false;
      for (let k = 0; k < labels.length; k++) {
        const l = labels[k]; if (k === active) running = true;
        if (!running) range(l.start, l.end);
        if (running && ts[l.end - 2]?.text === 'break') running = false;
      }
      return end + 1;
    }
    if (t === 'try') {
      // Preserve independent outer branch proofs, but treat exception paths
      // as opaque. All their assignments remain in the binding write set.
      let j = i + 1;
      if (ts[j]?.text === '(') { const end = pairs.get(j); if (end === undefined) throw new Error('resources'); j = end + 1; }
      const blockEnd = start => {
        const end = pairs.get(start);
        if (ts[start]?.text !== '{' || end === undefined) throw new Error('handler');
        return end + 1;
      };
      j = blockEnd(j);
      while (ts[j]?.text === 'catch') {
        if (ts[j + 1]?.text !== '(' || !pairs.has(j + 1)) throw new Error('catch');
        j = blockEnd(pairs.get(j + 1) + 1);
      }
      if (ts[j]?.text === 'finally') j = blockEnd(j + 1);
      return j;
    }
    if (t === 'do' || t === 'else' || t === 'catch' || t === 'finally') throw new Error('unsupported control');
    for (let j = i; j < ts.length; j++) {
      if (--work < 0 || ['{', '}'].includes(ts[j].text)) throw new Error('statement');
      if (ts[j].text === ';') return j + 1;
      if (pairs.has(j)) j = pairs.get(j);
    }
    throw new Error('statement');
  }
  try { for (let i = 0; i < ts.length;) i = statement(i); return dead; } catch { return []; }
}
module.exports = { evaluate, excludedBranches };
