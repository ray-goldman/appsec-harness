'use strict';
const path = require('node:path');

// This is capability flow, not request taint: a computed read might retrieve a
// constructor/function. It may be consumed as data, but must not become code.
// Unknown syntax, effects, bindings, calls or exhausted budgets retain alerts.
function computedDataOnly(project) {
  if (project.computedDataOnly !== undefined) return project.computedDataOnly;
  project.computedDataOnly = false;
  try { project.computedDataOnly = analyze(project); } catch { /* unknown */ }
  return project.computedDataOnly;
}

function analyze(project) {
  const sources = project.sources.filter(s => s.lang === 'javascript');
  if (sources.length > 200 || sources.reduce((n, s) => n + s.raw.length, 0) > 250000) return false;
  // Optional vendored parser. Its absence leaves the regex scanner operational.
  const { parse } = require('./parsers/acorn');
  const modules = new Map(), nodes = [], functions = new Map(), bindings = new Map(), scopes = new WeakMap();
  const parents = new WeakMap(), exportedProperties = new Set();
  const scope = (parent, kind) => ({ parent, kind, names: new Map() });
  const declare = (s, name) => {
    if (!s.names.has(name)) s.names.set(name, { scope: s, name });
    return s.names.get(name);
  };
  const reference = (node, name = node.name) => {
    let s = scopes.get(node);
    while (s) {
      if (s.names.has(name)) return s.names.get(name);
      if (!s.parent) return declare(s, name);
      s = s.parent;
    }
    throw Error('Missing scope');
  };
  const bind = (name, value) => {
    if (!bindings.has(name)) bindings.set(name, []);
    bindings.get(name).push(value);
  };
  const property = n => n && !n.computed && n.property?.type === 'Identifier' ? n.property.name : null;
  const fnType = n => /^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(n?.type);
  const params = pattern => {
    if (pattern.type === 'Identifier') return [pattern.name];
    if (pattern.type === 'ObjectPattern') return pattern.properties.flatMap(p => p.type === 'Property' ? params(p.value) : params(p.argument));
    if (pattern.type === 'ArrayPattern') return pattern.elements.filter(Boolean).flatMap(params);
    if (pattern.type === 'AssignmentPattern') return params(pattern.left);
    if (pattern.type === 'RestElement') return params(pattern.argument);
    throw Error('Unsupported binding');
  };
  for (const source of sources) {
    const ast = parse(source.raw, { ecmaVersion: 2022, sourceType: 'script' });
    const module = { ast, source, exports: new Map(), imports: [], exportValues: [], scope: scope(null, 'module') };
    modules.set(source.file, module);
    const stack = [{ node: ast, parent: null, fn: null, depth: 0, scope: module.scope }];
    while (stack.length) {
      const item = stack.pop(), { node, parent, depth } = item;
      if (depth > 160 || nodes.length >= 50000) return false;
      let lexical = item.scope;
      if (node.type === 'FunctionDeclaration' && node.id) declare(lexical, node.id.name);
      if (fnType(node)) lexical = scope(lexical, 'function');
      else if (node.type === 'BlockStatement' || node.type === 'CatchClause') lexical = scope(lexical, 'block');
      scopes.set(node, lexical);
      parents.set(node, parent);
      nodes.push({ ...item, module, scope: lexical });
      let fn = item.fn;
      if (fnType(node)) {
        fn = node;
        functions.set(node, { node, params: node.params, returns: [], scope: lexical });
        for (const p of node.params) for (const name of params(p)) {
          bind(name, { kind: 'value' });
          declare(lexical, name);
        }
        if (node.type === 'FunctionExpression' && node.id) declare(lexical, node.id.name);
        if (node.id) bind(node.id.name, { kind: 'function', fn: node });
        if (node.type === 'ArrowFunctionExpression' && node.body.type !== 'BlockStatement') functions.get(node).returns.push(node.body);
      }
      if (node.type === 'ReturnStatement' && node.argument && fn) functions.get(fn).returns.push(node.argument);
      if (node.type === 'VariableDeclarator') {
        let declarationScope = lexical;
        if (parent.kind === 'var') while (declarationScope.kind === 'block') declarationScope = declarationScope.parent;
        for (const name of params(node.id)) declare(declarationScope, name);
        const init = node.init;
        const load = init?.type === 'CallExpression' && init.callee.type === 'Identifier' &&
          init.callee.name === 'require' && init.arguments.length === 1 &&
          init.arguments[0].type === 'Literal' && typeof init.arguments[0].value === 'string';
        if (load) module.imports.push(node);
        else for (const name of params(node.id)) bind(name, fnType(init) ? { kind: 'function', fn: init } : { kind: 'value' });
      }
      if (node.type === 'CatchClause') for (const name of node.param ? params(node.param) : []) {
        bind(name, { kind: 'value' }); declare(lexical, name);
      }
      if (node.type === 'ClassDeclaration' && node.id) { bind(node.id.name, { kind: 'class' }); declare(lexical, node.id.name); }
      if (node.type === 'AssignmentExpression' && property(node.left) === 'exports' && node.left.object.type === 'Identifier' &&
          node.left.object.name === 'module' && node.operator === '=' && node.right.type === 'ObjectExpression') {
        module.exportValues.push(node.right);
        for (const p of node.right.properties) {
          if (p.type !== 'Property' || p.computed || p.kind !== 'init' || p.key.type !== 'Identifier' || p.value.type !== 'Identifier') continue;
          module.exports.set(p.key.name, p.value.name);
          exportedProperties.add(p);
        }
      }
      for (const [key, value] of Object.entries(node)) {
        if (key === 'start' || key === 'end') continue;
        const children = Array.isArray(value) ? value : [value];
        for (const child of children) if (child && typeof child.type === 'string') stack.push({ node: child, parent: node, fn, depth: depth + 1, scope: lexical });
      }
    }
  }
  const resolve = (file, specifier) => {
    if (!/^\.[/][A-Za-z0-9_./-]+$/.test(specifier)) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
    if (base.startsWith('../')) return null;
    const matches = [base, base + '.js', base + '/index.js'].filter(p => modules.has(p));
    return matches.length === 1 ? modules.get(matches[0]) : null;
  };
  for (const module of modules.values()) for (const declaration of module.imports) {
    const specifier = declaration.init.arguments[0].value;
    if (declaration.id.type === 'Identifier') {
      bind(declaration.id.name, { kind: 'module', specifier, owner: resolve(module.source.file, specifier) });
    } else if (declaration.id.type === 'ObjectPattern') {
      for (const p of declaration.id.properties) {
        if (p.type !== 'Property' || p.computed || p.key.type !== 'Identifier' || p.value.type !== 'Identifier') return false;
        if (['child_process', 'node:child_process'].includes(specifier) && p.key.name === 'exec') {
          bind(p.value.name, { kind: 'data-call' });
        } else {
          const owner = resolve(module.source.file, specifier);
          const exported = owner?.exports.get(p.key.name);
          // Resolve to declared source functions, never infer from helper names.
          const candidates = exported ? (bindings.get(exported) || []).filter(b => b.kind === 'function' || b.kind === 'class') : [];
          if (candidates.length !== 1) return false;
          bind(p.value.name, candidates[0]);
        }
      }
    } else return false;
  }
  const intrinsic = name => ['Number', 'String', 'require'].includes(name) && !bindings.has(name);
  const callTargets = callee => {
    if (callee.type !== 'Identifier') return null;
    const entries = bindings.get(callee.name) || [];
    return entries.length && entries.every(b => b.kind === 'function') ? [...new Set(entries.map(b => b.fn))] : null;
  };
  const dataCall = callee => callee.type === 'Identifier' && (bindings.get(callee.name) || []).length &&
    bindings.get(callee.name).every(b => b.kind === 'data-call');
  const dataMethods = new Set(['get', 'post', 'query', 'then', 'json', 'send', 'sendStatus',
    'replace', 'trim', 'test', 'basename', 'readFile', 'where', 'Router']);
  const literalData = node => node.type === 'Literal' ||
    (node.type === 'ObjectExpression' && node.properties.every(p =>
      p.type === 'Property' && !p.computed && p.kind === 'init' && literalData(p.value)));

  for (const { node, parent } of nodes) {
    if (node.type === 'Identifier' && node.name === 'module') {
      const use = parents.get(parent);
      if (parent?.type !== 'MemberExpression' || property(parent) !== 'exports' ||
          use?.type !== 'AssignmentExpression' || use.left !== parent) return false;
    }
    if (node.type === 'Identifier' && node.name === 'require' &&
        (bindings.has('require') || parent?.type !== 'CallExpression' || parent.callee !== node)) return false;
    if (node.type === 'Identifier') {
      const namespaces = (bindings.get(node.name) || []).filter(b => b.kind === 'module');
      if (namespaces.length && !(parent?.type === 'VariableDeclarator' && parent.id === node)) {
        const member = parent?.type === 'MemberExpression' && parent.object === node;
        const use = member && parents.get(parent);
        const direct = use?.type === 'CallExpression' && use.callee === parent;
        const constants = namespaces.every(b => b.owner?.exportValues.length === 1 && literalData(b.owner.exportValues[0]));
        if (!member || (!direct && !constants)) return false;
      }
    }
    // Function aliases can escape into member dispatch whose return value is
    // not modeled. Only declarations, direct calls and explicit exports are
    // admitted; destructured imports are binding sites rather than escapes.
    if (node.type === 'Identifier' && (bindings.get(node.name) || []).some(b => b.kind === 'function')) {
      const declaration = (fnType(parent) && parent.id === node) ||
        (parent?.type === 'VariableDeclarator' && parent.id === node && fnType(parent.init));
      const directCall = parent?.type === 'CallExpression' && parent.callee === node;
      const importBinding = parent?.type === 'Property' && parents.get(parent)?.type === 'ObjectPattern';
      if (!declaration && !directCall && !importBinding && !exportedProperties.has(parent)) return false;
    }
    // Iteration, exception values and constructor returns require flow models
    // beyond this bounded proof. Retain warnings for these forms.
    if (['ForOfStatement', 'ForInStatement', 'ThrowStatement', 'PropertyDefinition', 'StaticBlock', 'AssignmentPattern'].includes(node.type)) return false;
    if ((node.type === 'ClassDeclaration' || node.type === 'ClassExpression') && node.superClass) return false;
    if (node.type === 'MethodDefinition' && node.kind === 'constructor' &&
        functions.get(node.value)?.returns.length) return false;
    if (node.type === 'NewExpression' && (node.callee.type !== 'Identifier' ||
        !(bindings.get(node.callee.name) || []).length ||
        !bindings.get(node.callee.name).every(b => b.kind === 'class'))) return false;
    if (['WithStatement', 'ImportExpression', 'TaggedTemplateExpression', 'AwaitExpression', 'YieldExpression'].includes(node.type)) {
      // Awaiting ordinary calls occurs in the supplied routes; it does not
      // introduce a callable value by itself. Other forms remain unsupported.
      if (node.type !== 'AwaitExpression') return false;
    }
    if (node.type === 'Identifier' && ['Object', 'Reflect', 'Proxy', 'Function', 'eval',
      'arguments', 'global', 'globalThis', 'window', 'self', 'process', 'document', 'navigator',
      'location', 'setTimeout', 'setInterval', 'Worker', 'importScripts', 'Deno', 'Bun', 'WScript'].includes(node.name)) return false;
    if (node.type === 'Property' && (node.kind !== 'init' || node.computed)) return false;
    if (node.type === 'Property' && ['constructor', '__proto__', 'prototype', 'call', 'apply', 'bind']
      .includes(node.key.type === 'Identifier' ? node.key.name : node.key.value)) return false;
    if (node.type === 'MethodDefinition' && (node.kind === 'get' || node.kind === 'set' || node.computed)) return false;
    if (node.type === 'MemberExpression' && ['constructor', '__proto__', 'prototype', 'call', 'apply', 'bind'].includes(property(node))) return false;
    if (node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete')) return false;
    if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression') {
      const exported = property(node.left) === 'exports' && node.left.object.type === 'Identifier' && node.left.object.name === 'module';
      const field = !node.left.computed && node.left.object.type === 'ThisExpression';
      if ((!exported && !field) || node.operator !== '=') return false;
    }
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' &&
        (bindings.get(node.left.name) || []).some(b => b.kind !== 'value')) return false;
    if (node.type === 'CallExpression') {
      if (node.arguments.some(a => a.type === 'SpreadElement')) return false;
      if (node.callee.type === 'Identifier') {
        if (!intrinsic(node.callee.name) && !callTargets(node.callee) && !dataCall(node.callee)) return false;
        if (node.callee.name === 'require' && (node.arguments.length !== 1 ||
            node.arguments[0].type !== 'Literal' || typeof node.arguments[0].value !== 'string' ||
            ['vm', 'node:vm'].includes(node.arguments[0].value) ||
            !['VariableDeclarator', 'ExpressionStatement'].includes(parent?.type))) return false;
      } else if (node.callee.type !== 'MemberExpression' || !dataMethods.has(property(node.callee))) return false;
    }
  }
  const tainted = new Set(), returns = new Set();
  function capability(node, depth = 0) {
    if (!node) return false;
    if (depth > 160) throw Error('Expression budget');
    const cap = n => capability(n, depth + 1);
    switch (node.type) {
      case 'Identifier': return tainted.has(reference(node));
      case 'Literal': case 'ThisExpression': return false;
      case 'FunctionExpression': case 'ArrowFunctionExpression': return returns.has(node);
      case 'MemberExpression': return node.computed || cap(node.object);
      case 'CallExpression': {
        if (node.callee.type === 'Identifier' && intrinsic(node.callee.name)) return false;
        const targets = callTargets(node.callee);
        return targets ? targets.some(f => returns.has(f)) : cap(node.callee);
      }
      case 'NewExpression': return node.arguments.some(cap);
      case 'LogicalExpression': case 'AssignmentExpression': return cap(node.left) || cap(node.right);
      case 'ConditionalExpression': return cap(node.consequent) || cap(node.alternate);
      case 'SequenceExpression': return node.expressions.some(cap);
      case 'ArrayExpression': return node.elements.some(cap);
      case 'ObjectExpression': return node.properties.some(p => cap(p.value || p.argument));
      case 'SpreadElement': case 'AwaitExpression': return cap(node.argument);
      case 'UnaryExpression': case 'BinaryExpression': case 'TemplateLiteral': return false; // primitive result
      default: throw Error('Unsupported expression ' + node.type);
    }
  }
  let stable = false;
  for (let pass = 0; pass < 32; pass++) {
    const size = tainted.size + returns.size;
    for (const { node } of nodes) {
      // Direct function declarations have call summaries; escaped function
      // values still carry their capable returns through containers/factories.
      if (node.type === 'VariableDeclarator' && node.init && !fnType(node.init) && capability(node.init)) for (const name of params(node.id)) tainted.add(reference(node, name));
      if (node.type === 'AssignmentExpression' && capability(node.right)) {
        if (node.left.type === 'Identifier') tainted.add(reference(node.left));
        else if (node.left.type === 'MemberExpression' && node.left.object.type === 'Identifier') tainted.add(reference(node.left.object));
        else return false;
      }
      if (node.type === 'CallExpression') {
        const targets = callTargets(node.callee);
        if (targets) for (const f of targets) for (let i = 0; i < node.arguments.length; i++) {
          if (capability(node.arguments[i])) {
            if (!f.params[i] || f.params[i].type !== 'Identifier') return false;
            tainted.add(functions.get(f).scope.names.get(f.params[i].name));
          }
        }
      }
    }
    for (const [fn, summary] of functions) if (summary.returns.some(value => capability(value))) returns.add(fn);
    if (size === tainted.size + returns.size) { stable = true; break; }
  }
  if (!stable) return false;
  const capableExportNames = new Set([...exportedProperties].filter(p =>
    (bindings.get(p.value.name) || []).some(b => b.kind === 'function' && returns.has(b.fn))
  ).map(p => p.key.name));
  for (const { node } of nodes) {
    // Member calls have no receiver/dispatch summary. Do not discard a
    // capability returned by any locally declared object or class method.
    if ((node.type === 'MethodDefinition' || node.type === 'Property') &&
        fnType(node.value) && returns.has(node.value)) return false;
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') continue;
    // Exports are the sole permitted function alias. Member dispatch through
    // any matching export name cannot borrow a data-only return assumption.
    if (node.callee.type === 'MemberExpression' && capableExportNames.has(property(node.callee))) return false;
    if (capability(node.callee)) return false;
    if (node.arguments.some(a => capability(a))) {
      if (node.type === 'NewExpression') return false;
      if (!(node.callee.type === 'Identifier' && intrinsic(node.callee.name)) && !callTargets(node.callee) && !dataCall(node.callee)) return false;
    }
  }
  return true;
}

module.exports = { computedDataOnly };
