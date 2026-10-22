'use strict';

// Refine a low-confidence project heuristic, not an authentication proof.
// Unsupported files/parses keep the original evidence. Never execute source.
function authLoggingEvidence(file) {
  const original = { authCode: file.code, loggingCode: file.code };
  if (file.lang === 'python') return { ...original, authCode: require('./python-log-evidence').pythonAuthCode(file.code) };
  if (file.lang !== 'javascript' || !/\.(?:js|mjs|cjs)$/i.test(file.rel) ||
      Buffer.byteLength(file.code, 'utf8') > 200000) return original;
  try {
    const { parse } = require('./parsers/acorn');
    let ast;
    try { ast = parse(file.code, { ecmaVersion: 2022, sourceType: 'module', allowReturnOutsideFunction: false }); }
    catch { ast = parse(file.code, { ecmaVersion: 2022, sourceType: 'script' }); }
    const nodes = [], parents = new Map(), stack = [{ node: ast, parent: null, depth: 0 }];
    while (stack.length) {
      const item = stack.pop();
      if (item.depth > 160 || nodes.length >= 50000) return original;
      nodes.push(item);
      parents.set(item.node, item.parent);
      for (const value of Object.values(item.node)) {
        if (Array.isArray(value)) {
          for (const child of value) if (child?.type) stack.push({ node: child, parent: item.node, depth: item.depth + 1 });
        } else if (value?.type) stack.push({ node: value, parent: item.node, depth: item.depth + 1 });
      }
    }
    const auth = file.code.split('');
    const blank = (out, node) => {
      for (let i = node.start; i < node.end; i++) if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' ';
    };
    // Explicit shadowing, escaping or replacement of a browser owner makes its
    // navigation semantics unknown. Code-generation/reflection is unknown too.
    const owners = new Set(['location', 'window', 'document', 'self']);
    const unknownOwners = new Set();
    const called = new Set(nodes.filter(({ node }) => ['CallExpression', 'NewExpression'].includes(node.type) && node.callee.type === 'Identifier').map(({ node }) => node.callee.name));
    let reflective = false;
    for (const { node, parent } of nodes) {
      if (['WithStatement', 'ThisExpression', 'ImportDeclaration', 'ImportExpression'].includes(node.type)) reflective = true;
      // Computed calls and writes can recover constructors or replace owners.
      if (node.type === 'MemberExpression' && node.computed &&
          !(node.property.type === 'Literal' && typeof node.property.value === 'number') &&
          (['CallExpression', 'NewExpression', 'TaggedTemplateExpression'].includes(parent?.type) && (parent.callee === node || parent.tag === node) ||
           parent?.type === 'AssignmentExpression' && parent.left === node ||
           parent?.type === 'UpdateExpression' || parent?.type === 'UnaryExpression' && parent.operator === 'delete')) reflective = true;
      if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && called.has(node.id.name) &&
          node.init?.type === 'MemberExpression' && node.init.computed) reflective = true;
      const reflectName = /^(?:eval|Function|globalThis|global|constructor|require|defineProperty|defineProperties|setPrototypeOf|__defineSetter__)$/u;
      if (node.type === 'Identifier' && reflectName.test(node.name) || node.type === 'Literal' && typeof node.value === 'string' && reflectName.test(node.value)) reflective = true;
      if (node.type === 'MemberExpression' && !node.computed && node.property.name === 'location' &&
          node.object.type === 'Identifier' && owners.has(node.object.name) &&
          (parent?.type !== 'MemberExpression' || parent.object !== node || parent.computed)) unknownOwners.add(node.object.name);
      if (node.type !== 'Identifier' || !owners.has(node.name)) continue;
      if (parent?.type !== 'MemberExpression' || parent.object !== node || parent.computed) unknownOwners.add(node.name);
    }
    if (reflective) return original;
    for (const { node, parent } of nodes) {
      if (node.type !== 'Literal' || typeof node.value !== 'string') continue;
      const target = parent?.type === 'AssignmentExpression' && parent.operator === '=' && parent.right === node ? parent.left : null;
      const localPath = /^\/(?![\/\\])[^\\\u0000-\u0020\u007f]*$/u.test(node.value);
      const navigation = localPath && parents.get(parent)?.type === 'ExpressionStatement' &&
        target?.type === 'MemberExpression' && !target.computed && target.property.name === 'href' &&
        (target.object.type === 'Identifier' && target.object.name === 'location' && !unknownOwners.has('location') ||
         target.object.type === 'MemberExpression' && !target.object.computed && target.object.property.name === 'location' &&
         target.object.object.type === 'Identifier' && ['window', 'document', 'self'].includes(target.object.object.name) && !unknownOwners.has(target.object.object.name));
      if (navigation) blank(auth, node);
    }
    return { authCode: auth.join(''), loggingCode: file.code };
  } catch { return original; }
}

module.exports = { authLoggingEvidence };
