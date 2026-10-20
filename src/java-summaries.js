'use strict';
const { indexJavaFile, parseCall, argumentsOf, shadowsType } = require('./java-methods');
const unknown = () => ({ known: false, dependencies: [], encodings: [], evidence: [] });
const independent = () => ({ known: true, dependencies: [], encodings: [], evidence: [] });

// One context belongs to one immutable source file. Recursive proof state is
// carried explicitly; safe results are never cached across different arguments.
function createJavaSummaries({ file, raw, code, project }) {
  const index = indexJavaFile({ file, raw, code });
  let filter;
  function budget(context = {}) {
    return { ...context, budget: context.budget || { left: 10000, methods: new Set() }, stack: context.stack || [] };
  }
  function select(call) {
    if (!index.complete) return null;
    if (call.owner && call.owner !== 'this' && shadowsType(index, call.owner.split('.')[0])) return null;
    let target = { index, get filter() { return filter; } };
    if (call.owner && call.owner !== 'this' && call.owner !== index.className && call.owner !== index.qualifiedName) {
      target = project?.resolve(index, call.owner);
      if (!target) return null;
    }
    const matches = target.index.methods.filter(m => m.name === call.name);
    if (matches.length !== 1 || target.index.declarations.get(call.name) !== 1) return null;
    const method = matches[0];
    if (!method.supported || method.parameters.length !== call.args.length ||
        !(method.static || target.index === index && method.private) ||
        call.owner === 'this' && method.static) return null;
    if (target.index !== index && !method.static) return null;
    return { target, method };
  }
  function callFact({ expression, position, prove, context }) {
    const call = parseCall(expression), resolved = call && select(call);
    if (!resolved) return unknown();
    const { target, method } = resolved, state = budget(context);
    if (--state.budget.left < 0 || state.stack.length >= 4 || state.stack.includes(method.id)) return unknown();
    state.budget.methods.add(method.id);
    if (state.budget.methods.size > 32 || !method.returns.length || method.type !== 'String') return unknown();
    const parameters = new Map();
    for (let i = 0; i < method.parameters.length; i++) {
      const param = method.parameters[i];
      if (!['String', 'int', 'boolean', 'char', 'long'].includes(param.type)) return unknown();
      parameters.set(param.name, prove(call.args[i], 'constant') ? independent() : unknown());
    }
    const child = { ...state, stack: [...state.stack, method.id], parameters, parameterMethod: method.start };
    if (!target.filter) return unknown();
    const safe = method.returns.every(r => target.filter.valueAt(r.expression, r.offset, child));
    return safe ? independent() : unknown();
  }
  function parameterFact({ methodStart, name, context }) {
    const state = budget(context);
    if (state.parameterMethod === methodStart && state.parameters?.has(name)) return state.parameters.get(name);
    const method = index.methods.find(m => m.start === methodStart);
    if (!index.complete || !method?.supported || !method.private ||
        state.stack.includes(method.id) || state.stack.length >= 4) return unknown();
    const parameter = method.parameters.findIndex(p => p.name === name);
    if (parameter < 0 || !['String', 'int', 'boolean', 'char', 'long'].includes(method.parameters[parameter].type)) return unknown();
    if (index.declarations.get(method.name) !== 1) return unknown();
    state.budget.methods.add(method.id);
    if (state.budget.methods.size > 32) return unknown();
    const re = new RegExp(`\\b${method.name}\\b`, 'g');
    let calls = 0;
    for (const hit of index.mask.matchAll(re)) {
      if (hit.index === method.nameOffset) continue;
      if (--state.budget.left < 0 || ++calls > 64) return unknown();
      const following = index.mask.slice(hit.index + method.name.length);
      const open = following.match(/^\s*\(/);
      const caller = index.at(hit.index);
      if (!open || !caller) return unknown();
      const before = index.mask.slice(0, hit.index);
      const owner = before.match(/([\w.]+)\s*\.\s*$/)?.[1];
      if (owner && owner !== 'this' && !(method.static && owner === index.className)) return unknown();
      const begin = hit.index + method.name.length + open[0].length;
      let end = begin, depth = 1;
      for (; end < caller.end && depth; end++) {
        if (index.mask[end] === '(') depth++;
        if (index.mask[end] === ')') depth--;
      }
      const args = !depth && argumentsOf(index.code.slice(begin, end - 1));
      if (!args || args.length !== method.parameters.length ||
          !filter.valueAt(args[parameter], hit.index, { ...state, stack: [...state.stack, method.id] })) return unknown();
    }
    return calls ? independent() : unknown();
  }
  return { index, attach(value) { filter = value; }, callFact, parameterFact };
}

module.exports = { createJavaSummaries, unknown, independent };
