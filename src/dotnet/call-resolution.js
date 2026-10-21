'use strict';
function resolveCall(call,index) {
  const unresolved=reason=>({targets:[],status:'unresolved',reason});
  if(!call||typeof call.name!=='string'||!Number.isInteger(call.arity)||call.arity<0) return unresolved('incomplete-call');
  if(['namedArguments','optionalArguments','paramsArguments','extension','delegate','lambda','virtualDispatch','higherOrder'].some(key=>call[key])) return unresolved('unsupported-call-form');
  if(typeof call.receiverType!=='string'||!call.receiverType) return unresolved('insufficient-type-evidence');
  const candidates=index.methodLookup ? (index.methodLookup.get(JSON.stringify([call.receiverType,call.name,call.arity]))||[]) : index.methods.filter(m=>m.name===call.name&&m.arity===call.arity&&m.typeId===call.receiverType);
  if(candidates.length>1||candidates.some(m=>m.ambiguous)) return {targets:[],status:'ambiguous',reason:'multiple-compatible-targets'};
  const target=candidates[0];
  if(!target) return unresolved('no-compatible-target');
  if(target.unsupported) return unresolved('unsupported-declaration');
  if(!Array.isArray(call.argumentTypes)||call.argumentTypes.length!==call.arity||call.argumentTypes.some(t=>typeof t!=='string'||!t)) return unresolved('insufficient-type-evidence');
  if(!target.parameterTypes.every((type,i)=>typeof type==='string'&&type.replace(/\s+/g,'')===call.argumentTypes[i])) return unresolved('no-compatible-target');
  if(!target.static&&!call.instanceReceiver) return unresolved('instance-receiver-unresolved');
  return {targets:[target.id],status:'resolved',reason:null};
}
module.exports={resolveCall};
