'use strict';
// Cargo uses SemVer, not Maven/Python qualifier ordering. Keep this separate from legacy comparisons.
function parse(version) {
  if(typeof version!=='string'||version.length>256)return null;
  const m=version.match(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/);
  if(!m)return null;
  const pre=m[4]?.split('.')||[];
  if(pre.some(p=>/^[0-9]+$/.test(p)&&p.length>1&&p.startsWith('0')))return null;
  return {numbers:m.slice(1,4).map(BigInt),pre};
}
function compare(a,b) {
  const x=parse(a),y=parse(b);if(!x||!y)return NaN;
  for(let i=0;i<3;i++)if(x.numbers[i]!==y.numbers[i])return x.numbers[i]<y.numbers[i]?-1:1;
  if(!x.pre.length||!y.pre.length)return x.pre.length===y.pre.length?0:x.pre.length?-1:1;
  for(let i=0;i<Math.max(x.pre.length,y.pre.length);i++) {
    const l=x.pre[i],r=y.pre[i];if(l===r)continue;if(l==null||r==null)return l==null?-1:1;
    const ln=/^[0-9]+$/.test(l),rn=/^[0-9]+$/.test(r);
    if(ln&&rn)return BigInt(l)<BigInt(r)?-1:1;if(ln!==rn)return ln?-1:1;return l<r?-1:1;
  }
  return 0;
}
function inCargoRange(version,range) {
  return !!parse(version)&&(!range.introduced||range.introduced==='0'||compare(version,range.introduced)>=0)&&(!range.fixed||compare(version,range.fixed)<0);
}
module.exports={versionOK:v=>!!parse(v),inCargoRange};
