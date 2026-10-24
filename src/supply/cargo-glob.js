'use strict';
// Cargo workspace glob subset. Dynamic programming avoids attacker-controlled regex backtracking.
function workspaceGlob(pattern) {
  if(typeof pattern!=='string'||pattern.length>256||pattern.split('/').length>32||/[\\[\]{}]/.test(pattern)||pattern.startsWith('/')||pattern.split('/').includes('..'))throw Error('Unsupported workspace member pattern');
  const parts=pattern.replace(/^\.\//,'').replace(/\/$/,'').split('/');
  if(parts.some(p=>!p||p.includes('**')&&p!=='**'))throw Error('Unsupported workspace member pattern');
  return (value,tick)=>{
    if(value.length>2048)throw Error('Workspace path length budget exceeded');
    const segments=value.split('/');let state=new Array(segments.length+1).fill(false);state[0]=true;
    for(const part of parts) {
      const next=new Array(segments.length+1).fill(false);
      if(part==='**')for(let i=0;i<=segments.length;i++){tick();next[i]=state[i]||(i>0&&next[i-1]);}
      else for(let i=0;i<segments.length;i++)if(state[i]) {
        const segment=segments[i];let row=new Array(segment.length+1).fill(false);row[0]=true;
        for(const ch of part) {
          const after=new Array(segment.length+1).fill(false);after[0]=ch==='*'&&row[0];
          for(let j=1;j<=segment.length;j++){tick();after[j]=ch==='*'?(row[j]||after[j-1]):(ch==='?'||ch===segment[j-1])&&row[j-1];}
          row=after;
        }
        next[i+1]=row[segment.length];
      }
      state=next;
    }
    return state[segments.length];
  };
}
module.exports={workspaceGlob};
