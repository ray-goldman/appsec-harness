'use strict';
// Binding model only: the caller must still prove complete source/project input,
// unique literal const members, source visibility and absence of value shadows.
const profile=require('./frameworks/aspnetcore-controllerbase-net10.json');
const inherited=new Set(profile.inheritedNames);
const components=new Set(['Microsoft','AspNetCore','Mvc','ControllerBase']);
function createMvcConstOwnerProof(projects,types) {
 const decline=()=>false;
 if(projects.length!==1)return decline;
 const raw=projects[0].raw;
 if(!/^\s*<Project Sdk="Microsoft\.NET\.Sdk\.Web">/.test(raw))return decline;
 const targets=[...raw.matchAll(/<TargetFramework>([^<]+)<\/TargetFramework>/g)];
 if(targets.length!==1 || targets[0][1]!==profile.targetFramework)return decline;
 // A source type (even an inaccessible/unsupported one) makes namespace or
 // framework type lookup uncertain. Never infer external identity by name alone.
 if(types.some(type=>components.has(type.name)))return decline;
 return (owner,references)=>{
  const base=owner.header.map(t=>t.text).join('');
  if(base===':ControllerBase') {
   if(owner.file.namespace!=='Microsoft.AspNetCore.Mvc'&&!owner.file.imports.includes('Microsoft.AspNetCore.Mvc'))return false;
  } else if(![':Microsoft.AspNetCore.Mvc.ControllerBase',':global::Microsoft.AspNetCore.Mvc.ControllerBase'].includes(base))return false;
  return references.every(ref=>!inherited.has(ref.type));
 };
}
module.exports={createMvcConstOwnerProof};
