'use strict';
const { createMethodSummary } = require('./summary-schema');
const { tokenizeCSharp } = require('../parsers/csharp/lexer');
const { methodValues } = require('./value-flow');

// Straight-line diagnostic transfer only. Unsupported syntax is explicit;
// API spelling alone never proves that an argument is sanitized.
function summarizeMethod(method) {
  const parameters=method.parameters||[], body=method.body||'';
  const summary=createMethodSummary({methodId:method.id,parameters});
  const unresolved=reason=>summary.unresolvedCallSites.push({reason});
  if (body.length>1024*1024) {unresolved('body-limit');return summary;}
  const lex=tokenizeCSharp(body), ts=lex.tokens;
  if(ts.length>2048) {unresolved('token-limit');return summary;}
  const param=t=>t?.kind==='identifier'?parameters.findIndex(p=>p.name===t.text.replace(/^@/,'')):-1;
  if (lex.errors.length || ts.some(t=>['if','else','switch','for','foreach','while','do','try','catch','finally','goto','throw','=>','{','}'].includes(t.text))) {
    unresolved('unsupported-control-flow');return summary;
  }
  if (ts.some((t,i)=>param(t)>=0 && (['=','+=','-=','*=','/=','++','--','??='].includes(ts[i+1]?.text)||['++','--','ref','out'].includes(ts[i-1]?.text)))) {
    unresolved('parameter-write');return summary;
  }
  const values=methodValues(method);
  function matching(tokens,start) {
    let depth=0;
    for(let i=start;i<tokens.length;i++) {
      if(tokens[i].text==='(') depth++;
      if(tokens[i].text===')' && --depth===0) return i;
    }
    return -1;
  }
  function terms(tokens) {
    const value=values.valueAt(tokens);
    if(value.known) return value.parameters;
    while(tokens[0]?.text==='(' && matching(tokens,0)===tokens.length-1) tokens=tokens.slice(1,-1);
    let depth=0,start=0;const parts=[];
    for(let i=0;i<tokens.length;i++) {
      if(['(','['].includes(tokens[i].text)) depth++;
      if([')',']'].includes(tokens[i].text)) depth--;
      if(tokens[i].text==='+' && depth===0) {parts.push(tokens.slice(start,i));start=i+1;}
    }
    if(parts.length) return [...parts,tokens.slice(start)].flatMap(terms);
    return tokens.length===1 && param(tokens[0])>=0?[param(tokens[0])]:[];
  }
  function sourceCategory(tokens) {
    const value=values.valueAt(tokens);
    if(value.source) return value.source.source;
    for(let i=0;i+2<tokens.length;i++) if(tokens[i].text==='Request'&&tokens[i+1].text==='.'&&['Query','Form','Headers','Cookies','QueryString'].includes(tokens[i+2].text)) return 'request';
    return null;
  }
  const firstReturn=ts.findIndex(t=>t.text==='return');let end=ts.length;
  if(firstReturn>=0) {
    const semi=ts.findIndex((t,i)=>i>firstReturn && t.text===';');end=semi<0?ts.length:semi;
    const expression=ts.slice(firstReturn+1,end);
    summary.parameterToReturn=[...new Set(terms(expression))];
    if(expression[0]?.text==='Request' && expression[1]?.text==='.' && ['Query','Form','Headers','Cookies','QueryString'].includes(expression[2]?.text) && expression[3]?.text==='[' && expression.at(-1)?.text===']') summary.sourcesToReturn.push('request');
    if(!summary.parameterToReturn.length && !summary.sourcesToReturn.length && expression.some(t=>t.kind==='identifier'&&!['true','false','null'].includes(t.text))) unresolved('unsupported-return-expression');
  }
  for(let i=0;i<end;i++) {
    if(ts[i].text!=='(') continue;
    let j=i-1;if(ts[j]?.kind!=='identifier') continue;
    while(j>=2 && ts[j-1].text==='.' && ts[j-2].kind==='identifier') j-=2;
    const name=ts.slice(j,i).map(t=>t.text).join('');
    const category=/(?:^|\.)(?:ExecuteSqlRaw|FromSqlRaw|ExecuteSqlCommand|SqlCommand)$/.test(name)?'sql':
      ['Html.Raw','Response.Write'].includes(name)?'xss':name==='Process.Start'?'command':
      ['File.ReadAllText','File.ReadAllBytes','File.Delete','File.WriteAllText','PhysicalFile'].includes(name)?'path':null;
    const close=matching(ts,i);
    if(close<0) {unresolved('unbalanced-call');continue;}
    if(!category) {unresolved('unmodeled-call');continue;}
    let depth=0,argEnd=close;
    for(let k=i+1;k<close;k++) {
      if(['(','['].includes(ts[k].text)) depth++;
      if([')',']'].includes(ts[k].text)) depth--;
      if(ts[k].text===',' && depth===0) {argEnd=k;break;}
    }
    for(const parameter of new Set(terms(ts.slice(i+1,argEnd)))) {
      const line=(method.bodyLine||1)+body.slice(0,ts[i].start).split(/\r?\n/).length-1;
      summary.parameterToSinks.push({parameter,category,sanitized:false,sinkLocation:{file:method.file||'',line},callPath:[method.id]});
      summary.sanitizersBySink[category]=false;
    }
    const source=sourceCategory(ts.slice(i+1,argEnd));
    if(source) {
      const line=(method.bodyLine||1)+body.slice(0,ts[i].start).split(/\r?\n/).length-1;
      summary.sourcesToSinks.push({source,category,sourceLocation:{file:method.file||'',line},sinkLocation:{file:method.file||'',line},callPath:[method.id]});
    }
  }
  return summary;
}
module.exports={summarizeMethod};
