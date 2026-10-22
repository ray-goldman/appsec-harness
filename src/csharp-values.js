'use strict';

const { buildDotnetProjectIndex } = require('./dotnet/project-index');
const { tokenizeCSharp } = require('./parsers/csharp/lexer');
const SCALARS = new Set(['string', 'char', 'int', 'long', 'short', 'byte', 'bool', 'float', 'double', 'decimal']);
const id = token => token?.text.replace(/^@/, '');

function split(tokens, separator) {
  const result = []; let start = 0, depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    if (['(', '[', '{'].includes(tokens[i].text)) depth++;
    else if ([')', ']', '}'].includes(tokens[i].text)) depth--;
    else if (!depth && tokens[i].text === separator) { result.push(tokens.slice(start, i)); start = i + 1; }
  }
  result.push(tokens.slice(start));
  return result;
}

// This proof deliberately accepts a small subset. All syntactic writes count,
// including branches not selected by the current caller or build configuration.
function createCSharpValueProof(code, ast) {
  const lex = tokenizeCSharp(code);
  if (!ast.complete || lex.errors.length || lex.tokens.length > 20000) return () => false;
  const tokens = lex.tokens, pairs = new Map(), stack = [];
  const positions = new Map(tokens.map((token, i) => [token.start, i]));
  for (let i = 0; i < tokens.length; i++) {
    if (['(', '[', '{'].includes(tokens[i].text)) stack.push(i);
    else if ([')', ']', '}'].includes(tokens[i].text)) {
      const open = stack.pop(); pairs.set(open, i); pairs.set(i, open);
    }
  }
  const index = buildDotnetProjectIndex([{ file: 'proof.cs', source: code, ast }]);
  // Partial, nested and multiple types need a project-wide ownership proof.
  if (index.types.length !== 1 || index.types[0].partial || index.methods.length > 256 || index.diagnostics.truncated) return () => false;
  const owner = index.types[0], methods = index.methods;
  const models = new Map(), fields = new Map();
  for (const field of owner.fields) {
    const position = tokens.findIndex((token, i) => id(token) === field.name && tokens[i + 1]?.text === ';');
    if (position < 0 || !SCALARS.has(field.type) || ['String','var'].includes(field.type)) continue;
    let start = position - 1;
    while (start >= 0 && ![';', '{', '}'].includes(tokens[start].text)) start--;
    const prefix = tokens.slice(start + 1, position).map(t => t.text);
    if (!prefix.includes('private') || prefix.includes('volatile')) continue;
    fields.set(field.name, { key: 'field:' + field.name, name: field.name, declaration:tokens[position].start, field: true, writes: [], invalid: false });
  }
  function buildModel(method) {
    if (models.has(method.id)) return models.get(method.id);
    const ts = tokens.filter(t => t.start > method.bodyStart && t.end < method.bodyEnd);
    const root = { parent: null, bindings: new Map() }, scopes = new Map(), allBindings = [];
    for (const [n, parameter] of method.parameters.entries()) {
      const binding = { key: method.id + ':param:' + n, name: parameter.name, parameter: n, method, writes: [], invalid: false };
      root.bindings.set(parameter.name, binding); allBindings.push(binding);
    }
    let scope = root;
    const shadowedFields = new Set(ts.filter((t, i) => fields.has(id(t)) && ts[i - 1]?.kind === 'identifier' &&
      !['return','throw','await','yield'].includes(ts[i - 1].text) && !['=',';'].includes(ts[i + 1]?.text)).map(id));
    for (let i=0;i<ts.length;i++) if(ts[i].text==='catch'&&ts[i+1]?.text==='(') {
      const close=pairs.get(positions.get(ts[i+1].start)),name=close===undefined?null:id(tokens[close-1]);
      if(fields.has(name))shadowedFields.add(name);
    }
    for(const name of shadowedFields)fields.get(name).invalid=true;
    const invalid = method.end - method.start > 50000 || ts.some((t, i) => t.kind === 'interpolated-string' ||
      ['=>', 'ref', 'out', 'foreach', 'fixed', 'unsafe', 'goto', 'is', 'switch'].includes(t.text) ||
      t.text === '(' && pairs.has(positions.get(t.start)) && tokens[pairs.get(positions.get(t.start)) + 1]?.text === '{' &&
      !['if','while','for','switch','catch','using','lock'].includes(ts[i - 1]?.text));
    for (let i = 0; i < ts.length; i++) {
      const token = ts[i];
      if (token.text === '{') scope = { parent: scope, bindings: new Map() };
      scopes.set(token.start, scope);
      const previous=ts[i-1];
      const declaration=previous?.kind==='identifier'&&!['return','throw','await','yield'].includes(previous.text)||['>','?',']'].includes(previous?.text);
      if (token.kind === 'identifier' && declaration && ['=', ';'].includes(ts[i + 1]?.text)) {
        const name = id(token), duplicate = scope.bindings.has(name);
        const binding = { key: method.id + ':' + token.start, name, writes: [], invalid: duplicate || !SCALARS.has(previous.text) };
        if (duplicate) scope.bindings.get(name).invalid = true;
        scope.bindings.set(name, binding); allBindings.push(binding);
      }
      if (token.text === '}') scope = scope.parent || root;
    }
    function bindingAt(token) {
      const offset = positions.get(token.start), previous = tokens[offset - 1];
      if (previous?.text === '.') {
        if (tokens[offset - 2]?.text === 'this') return fields.get(id(token));
        return null;
      }
      let current = scopes.get(token.start);
      while (current) { if (current.bindings.has(id(token))) return current.bindings.get(id(token)); current = current.parent; }
      return shadowedFields.has(id(token)) ? null : fields.get(id(token));
    }
    const model = { method, ts, invalid, bindingAt, returns: [] };
    models.set(method.id, model);
    for (const token of ts) {
      const open = positions.get(token.start), close = pairs.get(open);
      if (token.text !== '(' || tokens[close + 1]?.text !== '=') continue;
      for (const item of tokens.slice(open + 1, close)) {
        const binding = item.kind === 'identifier' && bindingAt(item);
        if (binding) binding.invalid = true;
      }
    }
    for (let i = 0; i < ts.length; i++) {
      const token = ts[i];
      if (token.kind !== 'identifier') continue;
      const binding = bindingAt(token);
      if (binding && (['++','--','+=','-=','*=','/=','%=','??='].includes(ts[i + 1]?.text) ||
          ['++','--','ref','out'].includes(ts[i - 1]?.text) ||
          ['&','|','^','%','<','>'].includes(ts[i + 1]?.text) && ts[i + 2]?.text === '=')) binding.invalid = true;
      if (binding && ts[i + 1]?.text === '=') {
        if (binding.parameter !== undefined) binding.invalid = true;
        let end = i + 2, depth = 0;
        for (; end < ts.length; end++) {
          const text = ts[end].text;
          if (['(', '[', '{'].includes(text)) depth++;
          else if ([')', ']', '}'].includes(text)) { if (!depth) break; depth--; }
          else if (text === ';' && !depth) break;
        }
        if (ts[end]?.text !== ';') binding.invalid = true;
        else binding.writes.push({ expression: ts.slice(i + 2, end), model });
      }
      if (token.text === 'return') {
        let end = i + 1;
        while (end < ts.length && ts[end].text !== ';') end++;
        model.returns.push(ts.slice(i + 1, end));
      }
    }
    // An unsupported body can write a private field through syntax we don't model.
    if (invalid) for (const field of fields.values()) field.invalid = true;
    return model;
  }
  for (const method of methods) buildModel(method);
  const modelAt = token => token && [...models.values()].find(m => token.start > m.method.bodyStart && token.end < m.method.bodyEnd);
  for (const field of fields.values()) {
    // Explicit member access through any receiver other than this is unresolved.
    if (tokens.some((t, i) => id(t) === field.name && tokens[i - 1]?.text === '.' && tokens[i - 2]?.text !== 'this')) field.invalid = true;
    if (tokens.some(t => id(t) === field.name && t.start !== field.declaration && !modelAt(t))) field.invalid = true;
    if (tokens.some(t => t.kind === 'interpolated-string' || ['GetField','GetFields','SetValue','DynamicInvoke'].includes(t.text))) field.invalid = true;
  }
  const targets = name => methods.filter(m => m.name === name);
  const shadowedName = name => methods.some(method => method.parameters.some(parameter => parameter.name === name)) ||
    tokens.some((t, i) => id(t) === name && tokens[i - 1]?.text !== '.' && ['=', ';'].includes(tokens[i + 1]?.text));
  function helper(name) {
    const matches = targets(name);
    if (matches.length !== 1 || matches[0].unsupported || matches[0].ambiguous || matches[0].visibility !== 'private') return null;
    // A same-spelled local/delegate makes ownership uncertain.
    if (shadowedName(name)) return null;
    return models.get(matches[0].id);
  }
  function proveBinding(binding, visiting, depth) {
    if (!binding || binding.invalid || visiting.has(binding.key)) return false;
    const next = new Set(visiting); next.add(binding.key);
    if (binding.parameter !== undefined) {
      if (!['string','char','int','long','short','byte','bool','float','double','decimal'].includes(binding.method.parameterTypes[binding.parameter])) return false;
      const target = helper(binding.method.name);
      if (!target) return false;
      let sites = 0;
      for (let i = 0; i < tokens.length; i++) {
        if (id(tokens[i]) !== target.method.name || tokens[i].start === target.method.start) continue;
        if (tokens[i + 1]?.text !== '(' || !pairs.has(i + 1) ||
            tokens[i - 1]?.text === '.' && !['this', owner.name].includes(id(tokens[i - 2]))) return false;
        if (tokens[i - 1]?.text === '.' && id(tokens[i - 2]) === owner.name && shadowedName(owner.name)) return false;
        const caller = modelAt(tokens[i]);
        if (!caller || caller.invalid) return false;
        const args = split(tokens.slice(i + 2, pairs.get(i + 1)), ',');
        if (args.length !== target.method.arity || !prove(args[binding.parameter], caller, next, depth + 1)) return false;
        sites++;
      }
      return sites > 0;
    }
    return (binding.field || binding.writes.length > 0) && binding.writes.every(write => !write.model.invalid && prove(write.expression, write.model, next, depth + 1));
  }
  function prove(expression, model, visiting = new Set(), depth = 0) {
    if (!model || model.invalid || !expression?.length || expression.length > 256 || depth > 24) return false;
    while (expression[0]?.text === '(' && expression.at(-1)?.text === ')' &&
        pairs.get(positions.get(expression[0].start)) === positions.get(expression.at(-1).start)) expression = expression.slice(1, -1);
    const parts = split(expression, '+');
    if (parts.length > 1) return parts.every(part => prove(part, model, visiting, depth + 1));
    if (expression.length === 1) {
      const token = expression[0];
      if (['string','char','number'].includes(token.kind) || ['true','false','null'].includes(token.text)) return true;
      return token.kind === 'identifier' && proveBinding(model.bindingAt(token), visiting, depth + 1);
    }
    if (expression.length === 3 && expression[0].text === 'this' && expression[1].text === '.') return proveBinding(fields.get(id(expression[2])), visiting, depth + 1);
    let open = expression.findIndex(t => t.text === '(');
    if (open < 1 || pairs.get(positions.get(expression[open].start)) !== positions.get(expression.at(-1).start)) return false;
    const prefix = expression.slice(0, open);
    if (!(prefix.length === 1 || prefix.length === 3 && prefix[1].text === '.' && ['this', owner.name].includes(id(prefix[0])))) return false;
    if (prefix.length === 3 && id(prefix[0]) !== 'this' && shadowedName(id(prefix[0]))) return false;
    const callee = helper(id(prefix.at(-1)));
    const args = expression.length === open + 2 ? [] : split(expression.slice(open + 1, -1), ',');
    if (!callee || callee.method.arity !== args.length || !callee.returns.length || visiting.has(callee.method.id)) return false;
    const nameIndex=positions.get(callee.method.start);
    if (!['string','char','int','long','short','byte','bool','float','double','decimal'].includes(tokens[nameIndex-1]?.text)) return false;
    const next = new Set(visiting); next.add(callee.method.id);
    return callee.returns.every(result => prove(result, callee, next, depth + 1));
  }
  return expression => prove(expression, modelAt(expression?.[0]));
}

module.exports = { createCSharpValueProof };

