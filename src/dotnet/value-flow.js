'use strict';
const { tokenizeCSharp } = require('../parsers/csharp/lexer');
const cache = new WeakMap();
const unknown = () => ({ known:false, constant:false, parameters:[], type:null, source:null });

// Transfer for straight-line scalar locals only. Callers reject control flow
// before consuming it; unknown writes kill the previous value.
function methodValues(method) {
  if (cache.has(method)) return cache.get(method);
  const tokens = tokenizeCSharp(method.body || '').tokens;
  const environment = new Map((method.parameters || []).map((p, i) => [p.name,{known:true,constant:false,parameters:[i],type:p.type,source:null}]));
  const history = [{ offset:-1, values:new Map(environment) }];
  function evaluate(expression, values) {
    if (!expression.length || expression.length > 256) return unknown();
    while (expression[0]?.text === '(' && expression.at(-1)?.text === ')') {
      let depth=0,wraps=true;
      for(let i=0;i<expression.length;i++) {if(expression[i].text==='(')depth++;else if(expression[i].text===')'&&--depth===0&&i<expression.length-1){wraps=false;break;}}
      if(!wraps) break; expression=expression.slice(1,-1);
    }
    let depth=0,start=0;const parts=[];
    for(let i=0;i<expression.length;i++) {
      if(['(','['].includes(expression[i].text))depth++;
      if([')',']'].includes(expression[i].text))depth--;
      if(expression[i].text==='+'&&!depth){parts.push(expression.slice(start,i));start=i+1;}
    }
    if(parts.length) {
      const flows=[...parts,expression.slice(start)].map(part=>evaluate(part,values));
      if(flows.some(flow=>!flow.known)) return unknown();
      return {known:true,constant:flows.every(flow=>flow.constant),parameters:[...new Set(flows.flatMap(flow=>flow.parameters))],
        type:flows.some(flow=>flow.type==='string')?'string':null,source:flows.find(flow=>flow.source)?.source||null};
    }
    if(expression.length===1) {
      const token=expression[0];
      if(token.kind==='identifier'&&values.has(token.text.replace(/^@/,'')))return values.get(token.text.replace(/^@/,''));
      const type=token.kind==='string'?'string':token.kind==='char'?'char':token.kind==='number'&&/^\d+$/.test(token.text)?'int':['true','false'].includes(token.text)?'bool':null;
      return type?{known:true,constant:true,parameters:[],type,source:null}:unknown();
    }
    if(expression[0]?.text==='Request'&&expression[1]?.text==='.'&&['Query','Form','Headers','Cookies','QueryString'].includes(expression[2]?.text)&&expression[3]?.text==='[') {
      let close=4;while(close<expression.length&&expression[close].text!==']')close++;
      const suffix=expression.slice(close+1).map(t=>t.text).join('');
      if(close<expression.length&&['','.ToString()'].includes(suffix)) return {known:true,constant:false,parameters:[],type:suffix?'string':null,source:{source:'request',offset:expression[0].start}};
    }
    return unknown();
  }
  const valueAt = (expression, offset=expression[0]?.start??0) => {
    let state=history[0].values;
    for(const item of history){if(item.offset>=offset)break;state=item.values;}
    return evaluate(expression,state);
  };
  for(let i=0;i<tokens.length;i++) {
    const token=tokens[i];
    if(token.kind!=='identifier'||tokens[i-1]?.text==='.')continue;
    const name=token.text.replace(/^@/,''),next=tokens[i+1]?.text;
    if(next==='=') {
      let end=i+2,depth=0;
      for(;end<tokens.length;end++) {
        if(['(','['].includes(tokens[end].text))depth++;
        else if([')',']'].includes(tokens[end].text))depth--;
        if(tokens[end].text===';'&&!depth)break;
      }
      const value=tokens[end]?.text===';'?evaluate(tokens.slice(i+2,end),environment):unknown();
      // Only declarations or previously tracked names have local identity.
      if(environment.has(name)||['string','String','var','int','char','bool'].includes(tokens[i-1]?.text)) {
        environment.set(name,value);history.push({offset:tokens[end]?.start??token.end,values:new Map(environment)});
      }
    } else if(environment.has(name)&&(['+=','-=','*=','/=','++','--','??='].includes(next)||['ref','out','++','--'].includes(tokens[i-1]?.text))) {
      environment.set(name,unknown());history.push({offset:token.start,values:new Map(environment)});
    }
  }
  const result={tokens,valueAt};cache.set(method,result);return result;
}
module.exports={methodValues};

