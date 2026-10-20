'use strict';
const path = require('node:path');
const { computedDataOnly } = require('./js-computed');

const id = (n, name) => n?.type === 'Identifier' && (name === undefined || n.name === name);
const member = (n, name) => n?.type === 'MemberExpression' && !n.computed && id(n.property, name);
const literal = (n, value) => n?.type === 'Literal' && n.value === value;
const exported = n => n?.type === 'ExpressionStatement' && n.expression.type === 'AssignmentExpression' &&
  n.expression.operator === '=' && member(n.expression.left, 'exports') && id(n.expression.left.object, 'module');

// Separate from request taint: discharge only a direct exec candidate with
// either typed validation or a closed, literal configuration dependency.
function javascriptCommandSafe(file, line, project) {
  if (!project.commandLines) {
    project.commandLines = new Map();
    try { project.commandLines = analyze(project); } catch { /* unknown retains warning */ }
  }
  return project.commandLines.get(file)?.has(line) || false;
}

function analyze(project) {
  const safe = new Map();
  if (!project.complete || !computedDataOnly(project)) return safe;
  const { parse } = require('./parsers/acorn');
  const modules = new Map(), nodes = [];
  for (const source of project.sources.filter(s => s.lang === 'javascript')) {
    const ast = parse(source.raw, { ecmaVersion: 2022, sourceType: 'script', locations: true });
    const mod = { source, ast, imports: new Map() };
    modules.set(source.file, mod);
    const stack = [{ node: ast, parent: null, depth: 0 }];
    while (stack.length) {
      const item = stack.pop();
      if (item.depth > 160 || nodes.length >= 50000) return safe;
      nodes.push({ ...item, mod });
      for (const value of Object.values(item.node)) for (const child of Array.isArray(value) ? value : [value]) {
        if (child && typeof child.type === 'string') stack.push({ node: child, parent: item.node, depth: item.depth + 1 });
      }
    }
  }
  // Explicit .js paths avoid package.json, extension and directory resolution.
  // Unresolved/external dependencies cannot establish export ownership.
  for (const { node, parent, mod } of nodes) {
    if (node.type === 'AssignmentExpression' && !exported(parent)) return safe;
    if (node.type !== 'CallExpression' || !id(node.callee, 'require')) continue;
    const spec = node.arguments[0]?.value;
    if (parent?.type !== 'VariableDeclarator' || parent.init !== node || typeof spec !== 'string') return safe;
    const declaration = mod.ast.body.find(s => s.type === 'VariableDeclaration' && s.kind === 'const' &&
      s.declarations.length === 1 && s.declarations[0] === parent);
    if (!declaration) return safe;
    const builtin = ['child_process', 'node:child_process'].includes(spec);
    const target = /^\.\/[A-Za-z0-9_./-]+\.js$/.test(spec) ?
      path.posix.normalize(path.posix.join(path.posix.dirname(mod.source.file), spec)) : null;
    const owner = target && !target.startsWith('../') ? modules.get(target) : null;
    if (!builtin && !owner) return safe;
    if (id(parent.id)) {
      if (builtin) return safe;
      mod.imports.set(parent.id.name, { owner, declaration: parent });
    } else if (parent.id.type === 'ObjectPattern' && parent.id.properties.length === 1) {
      const p = parent.id.properties[0];
      if (p.type !== 'Property' || p.computed || !id(p.key) || !id(p.value) || p.key.name !== p.value.name) return safe;
      if (builtin && p.key.name !== 'exec') return safe;
      mod.imports.set(p.value.name, { owner, builtin, name: p.key.name, declaration: parent });
    } else return safe;
  }

  function configValues(owner) {
    if (owner.ast.body.length !== 1 || !exported(owner.ast.body[0])) return null;
    const value = owner.ast.body[0].expression.right;
    if (value.type !== 'ObjectExpression') return null;
    const values = new Map();
    for (const p of value.properties) {
      if (p.type !== 'Property' || p.computed || p.kind !== 'init' || !id(p.key) ||
          p.value.type !== 'Literal' || typeof p.value.value !== 'string' || values.has(p.key.name)) return null;
      values.set(p.key.name, p.value.value);
    }
    return values;
  }
  function guardedHelper(owner, name) {
    const [fn, exp] = owner.ast.body;
    if (owner.ast.body.length !== 2 || fn.type !== 'FunctionDeclaration' || !id(fn.id, name) ||
        fn.async || fn.generator || fn.params.length !== 1 || !id(fn.params[0]) ||
        fn.body.body.length !== 1 || fn.body.body[0].type !== 'ReturnStatement' || !exported(exp)) return false;
    const value = exp.expression.right, p = value.properties?.[0];
    if (value.type !== 'ObjectExpression' || value.properties.length !== 1 || p.type !== 'Property' ||
        p.computed || p.kind !== 'init' || !id(p.key, name) || !id(p.value, name)) return false;
    const parameter = fn.params[0].name, terms = [];
    const flatten = n => n?.type === 'LogicalExpression' && n.operator === '&&' ?
      (flatten(n.left), flatten(n.right)) : terms.push(n);
    flatten(fn.body.body[0].argument);
    if (terms.length !== 4) return false;
    const [type, minimum, maximum, characters] = terms;
    const length = n => member(n, 'length') && id(n.object, parameter);
    if (type?.type !== 'BinaryExpression' || type.operator !== '===' ||
        type.left.type !== 'UnaryExpression' || type.left.operator !== 'typeof' ||
        !id(type.left.argument, parameter) || !literal(type.right, 'string')) return false;
    if (minimum?.type !== 'BinaryExpression' || minimum.operator !== '>' || !length(minimum.left) || !literal(minimum.right, 0) ||
        maximum?.type !== 'BinaryExpression' || maximum.operator !== '<=' || !length(maximum.left) || !literal(maximum.right, 253)) return false;
    const call = characters?.argument, regex = call?.callee?.object;
    return characters?.type === 'UnaryExpression' && characters.operator === '!' && call?.type === 'CallExpression' &&
      member(call.callee, 'test') && regex?.type === 'Literal' && regex.regex?.pattern === '[^a-z0-9.-]' &&
      regex.regex.flags === 'i' && call.arguments.length === 1 && id(call.arguments[0], parameter);
  }
  for (const mod of modules.values()) {
    if (!mod.imports.get('exec')?.builtin) continue;
    const configs = new Map();
    for (const [name, imp] of mod.imports) {
      if (!imp.owner || imp.name) continue;
      const values = configValues(imp.owner);
      // Every namespace reference must be a read of a known primitive field.
      if (values && nodes.filter(n => n.mod === mod && id(n.node, name)).every(({ node, parent }) =>
        node === imp.declaration.id || (parent?.type === 'MemberExpression' && parent.object === node &&
          !parent.computed && id(parent.property) && values.has(parent.property.name)))) configs.set(name, values);
    }
    function constant(n) {
      if (n.type === 'Literal') return typeof n.value === 'string';
      if (n.type === 'BinaryExpression' && n.operator === '+') return constant(n.left) && constant(n.right);
      return n.type === 'MemberExpression' && !n.computed && id(n.object) && id(n.property) &&
        configs.get(n.object.name)?.has(n.property.name);
    }
    for (const fn of mod.ast.body.filter(n => n.type === 'FunctionDeclaration')) {
      if (fn.async || fn.generator || fn.params.some(p => !id(p) || mod.imports.has(p.name))) continue;
      const statements = fn.body.body, statement = statements.at(-1), call = statement?.expression;
      if (statement?.type !== 'ExpressionStatement' || call?.type !== 'CallExpression' || !id(call.callee, 'exec') ||
          call.arguments.length !== 1 || statement.loc.start.line !== statement.loc.end.line) continue;
      const line = statement.loc.start.line - 1;
      if (mod.source.raw.split(/\r?\n/)[line].trim() !== mod.source.raw.slice(statement.start, statement.end)) continue;
      let proved = statements.length === 1 && constant(call.arguments[0]);
      if (!proved && statements.length === 3) {
        const [decl, guard] = statements, arg = call.arguments[0];
        const binding = decl.type === 'VariableDeclaration' && decl.kind === 'const' && decl.declarations.length === 1 ? decl.declarations[0] : null;
        const host = binding?.id?.name, init = binding?.init;
        const request = member(init) && member(init.object) && ['query', 'body', 'params'].includes(init.object.property.name) &&
          fn.params.some(p => id(init.object.object, p.name));
        const test = guard.type === 'IfStatement' && !guard.alternate && guard.test.type === 'UnaryExpression' && guard.test.operator === '!' ? guard.test.argument : null;
        const check = test?.type === 'CallExpression' && id(test.callee) ? mod.imports.get(test.callee.name) : null;
        proved = id(binding?.id) && request && guard.consequent?.type === 'ReturnStatement' && !guard.consequent.argument &&
          test?.arguments.length === 1 && id(test.arguments[0], host) && check?.owner && check.name && guardedHelper(check.owner, check.name) &&
          arg.type === 'BinaryExpression' && arg.operator === '+' && arg.left.type === 'Literal' &&
          ['ping -c1 ', 'nslookup '].includes(arg.left.value) && id(arg.right, host);
      }
      if (proved) { if (!safe.has(mod.source.file)) safe.set(mod.source.file, new Set()); safe.get(mod.source.file).add(line); }
    }
  }
  return safe;
}
module.exports = { javascriptCommandSafe };
