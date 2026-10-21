'use strict';

function resolveCall(call, index) {
  const unsupported = ['namedArguments','optionalArguments','paramsArguments','extension','delegate','lambda','virtualDispatch','higherOrder'].some(key => call[key]);
  if (unsupported || !call || typeof call.name !== 'string' || !Number.isInteger(call.arity)) return { targets: [], status: 'unresolved', reason: unsupported ? 'unsupported-call-form' : 'incomplete-call' };
  let candidates = index.methods.filter(method => method.name === call.name && method.arity === call.arity);
  if (call.receiverType) candidates = candidates.filter(method => method.typeId === call.receiverType || method.typeId.endsWith(`.${call.receiverType}`));
  if (Array.isArray(call.argumentTypes)) candidates = candidates.filter(method => method.parameterTypes.every((type, i) => !type || type.replace(/\s+/g,'') === call.argumentTypes[i]));
  if (candidates.length === 1 && call.receiverType && Array.isArray(call.argumentTypes)) return { targets: [candidates[0].id], status: 'resolved', reason: null };
  if (candidates.length > 1) return { targets: [], status: 'ambiguous', reason: 'multiple-compatible-targets' };
  return { targets: [], status: 'unresolved', reason: candidates.length === 1 ? 'insufficient-type-evidence' : 'no-compatible-target' };
}

module.exports = { resolveCall };
