'use strict';

// A removal-only proof: parse the complete file, then prove every DOM sink
// overlapping a reported line has exclusively fixed primitive HTML. No binding,
// helper, or sanitizer names are trusted. Unknown syntax/budgets retain alerts.
function createDomConstantProof(raw, file) {
  let byLine;
  return line => {
    if (byLine === undefined) {
      byLine = new Map();
      try { byLine = analyze(raw, file); } catch { /* optional parser / unknown */ }
    }
    const sinks = byLine.get(line + 1);
    return !!sinks?.length && sinks.every(Boolean);
  };
}

function primitive(node) {
  if (!node) return false;
  switch (node.type) {
    case 'Literal':
      return node.value === null || ['string', 'number', 'boolean'].includes(typeof node.value);
    case 'TemplateLiteral':
      return node.expressions.every(primitive);
    case 'ConditionalExpression':
      return primitive(node.consequent) && primitive(node.alternate);
    case 'LogicalExpression':
      return ['??', '||'].includes(node.operator) && primitive(node.left) && primitive(node.right);
    case 'BinaryExpression':
      return node.operator === '+' && primitive(node.left) && primitive(node.right);
    default:
      return false;
  }
}

function analyze(raw, file) {
  const result = new Map();
  if (!/\.(?:js|mjs|cjs)$/i.test(file) || Buffer.byteLength(raw, 'utf8') > 200000) return result;
  // Acorn counts these as line endings, but the regex scanner splits only LF
  // and CRLF. Never apply a proof whose line numbers could refer elsewhere.
  if (/\r(?!\n)|[\u2028\u2029]/.test(raw)) return result;
  const { parse } = require('./parsers/acorn');
  let ast;
  try { ast = parse(raw, { ecmaVersion: 2022, sourceType: 'module', locations: true }); }
  catch { ast = parse(raw, { ecmaVersion: 2022, sourceType: 'script', locations: true }); }
  const nodes = [], stack = [{ node: ast, depth: 0 }];
  while (stack.length) {
    const { node, depth } = stack.pop();
    if (depth > 160 || nodes.length >= 50000) return new Map();
    nodes.push(node);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (child?.type) stack.push({ node: child, depth: depth + 1 });
      } else if (value?.type) stack.push({ node: value, depth: depth + 1 });
    }
  }
  const name = member => {
    if (member?.type !== 'MemberExpression') return null;
    if (!member.computed) return member.property.name;
    return member.property.type === 'Literal' && typeof member.property.value === 'string' ? member.property.value : null;
  };
  const unknownMember = member => member?.type === 'MemberExpression' && member.computed && name(member) === null;
  const pattern = target => ['ObjectPattern', 'ArrayPattern'].includes(target?.type);
  for (const node of nodes) {
    let safe;
    if (node.type === 'AssignmentExpression' && ['innerHTML', 'outerHTML'].includes(name(node.left))) {
      safe = node.operator === '=' && primitive(node.right);
    } else if (node.type === 'CallExpression') {
      const method = name(node.callee);
      if (method === 'insertAdjacentHTML') {
        safe = node.arguments.length === 2 && primitive(node.arguments[1]);
      } else if (['write', 'writeln'].includes(method)) {
        safe = node.arguments.length > 0 && node.arguments.every(primitive);
      } else if (['html', 'append', 'prepend', 'after', 'before', 'replaceWith'].includes(method)) {
        // Include all method receivers conservatively: a second unmodeled DOM
        // operation on the same line must never be hidden by a fixed first one.
        safe = node.arguments.length > 0 && node.arguments.every(primitive);
      }
    }
    // A computed write or invocation may name a DOM sink at runtime. Retain
    // the line's existing alert rather than hiding it behind another fixed sink.
    if ((node.type === 'AssignmentExpression' && unknownMember(node.left)) ||
        (node.type === 'CallExpression' && unknownMember(node.callee))) safe = false;
    // Destructuring defaults and iteration targets also perform writes. Keep
    // destructuring unknown rather than trying to prove each target or default.
    if ((node.type === 'AssignmentPattern' &&
         (['innerHTML', 'outerHTML'].includes(name(node.left)) || unknownMember(node.left) || pattern(node.left))) ||
        (node.type === 'AssignmentExpression' && pattern(node.left)) ||
        (['ForInStatement', 'ForOfStatement'].includes(node.type) &&
         (node.left.type === 'MemberExpression' || pattern(node.left)))) safe = false;
    if (safe === undefined) continue;
    for (let line = node.loc.start.line; line <= node.loc.end.line; line++) {
      if (!result.has(line)) result.set(line, []);
      result.get(line).push(safe);
    }
  }
  return result;
}

module.exports = { createDomConstantProof };
