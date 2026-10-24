'use strict';

const { tokenizeCSharp } = require('./parsers/csharp/lexer');
const { parseCSharp } = require('./parsers/csharp/parser');
const ownerCache = new WeakMap();
const authName = /login|authenticate|signin(?!g)|verifyPassword|password_verify|check_password|compare_digest/i;
const exactAuthName = /^(?:login|authenticate|signin|verifyPassword|password_verify|check_password|compare_digest)$/i;

// Evidence for a missing-logging heuristic, not proof of audit completeness or
// delivery. Only ordinary structured paths are modeled; exceptions and sink
// collection/retention require human review.
function csharpConsoleAuthEvidence(code, context) {
  if (typeof code !== 'string' || code.length > 200000) return false;
  const lex = tokenizeCSharp(code), ast = parseCSharp(code), ts = lex.tokens;
  if (!ast.complete || lex.errors.length || lex.regions.some(r => r.kind === 'directive') || ts.length > 20000) return false;
  const pairs = new Map(), stack = [];
  for (let i=0;i<ts.length;i++) {
    if (['(', '[', '{'].includes(ts[i].text)) stack.push(i);
    else if ([')', ']', '}'].includes(ts[i].text)) { const open=stack.pop(); pairs.set(open,i); }
  }
  if (!ts.some((t,i) => t.text==='using' && ts[i+1]?.text==='System' && ts[i+2]?.text===';')) return false;
  // Explicit aliases, fields, parameters, custom owners and inherited/generic
  // owners can change the meaning of Console. Decline those source shapes.
  const name=t=>t?.text.replace(/^@/,'');
  function ownersClosed(tokens) {
    return !tokens.some((t,i) => t.text==='\\' || t.text==='using' && tokens[i+2]?.text==='=' ||
      name(t)==='Console' && !(tokens[i+1]?.text==='.' && name(tokens[i+2])==='WriteLine' && tokens[i+3]?.text==='(') ||
      t.text==='namespace' && name(tokens[i+1])==='System' ||
      ['class','struct','record','interface'].includes(t.text) && name(tokens[i+1])==='System');
  }
  if (!ownersClosed(ts)) return false;
  for (const declaration of ast.declarations) {
    const start=ts.findIndex(t=>t.start===declaration.start), open=ts.findIndex((t,i)=>i>start&&t.text==='{');
    if(open<0 || ts.slice(start,open).some(t=>[':', '<', 'partial'].includes(t.text)) || ts[start-1]?.text==='partial') return false;
  }
  const methods=ast.methods.filter(m=>authName.test(m.name));
  if(!methods.length || methods.length>64) return false;
  if(ts.some((t,i)=>t.kind==='identifier' && exactAuthName.test(name(t)) &&
      !methods.some(m=>m.start===t.start || m.name===name(t) && ts[i+1]?.text==='('))) return false;
  if(ts.some((t,i)=>t.kind==='identifier' && authName.test(name(t)) && ['=','{','=>'].includes(ts[i+1]?.text) &&
      !['class','struct','record','interface','namespace'].includes(ts[i-1]?.text) &&
      !methods.some(m=>m.start<=t.start&&m.end>=t.end))) return false;
  // Expression-bodied and generic declarations can be omitted by the bounded
  // structural parser. Do not let a supported sibling hide them.
  if(ts.some((t,i)=>t.kind==='identifier' && authName.test(name(t)) &&
      ['(','<'].includes(ts[i+1]?.text) &&
      (ts[i+1]?.text==='<' || ['{','=>'].includes(ts[pairs.get(i+1)+1]?.text) ||
       ts[i-1]?.kind==='identifier' && !['await','return','throw','new','nameof'].includes(ts[i-1].text) || ['>','?',']'].includes(ts[i-1]?.text)) &&
      !methods.some(m=>m.start===t.start))) return false;
  const covered=methods.every(method=>{
    const start=ts.findIndex(t=>t.start===method.bodyStart), end=pairs.get(start);
    if(end===undefined || end-start>5000) return false;
    const body=ts.slice(start+1,end);
    if(body.some(t=>[':', '=>','try','catch','finally','for','foreach','while','do','switch','goto','yield','throw','unsafe','fixed','lock'].includes(t.text))) return false;
    // No constant propagation is attempted in control predicates. Decline
    // literal flags and local Boolean declarations rather than count dead arms.
    if(body.some((t,i)=>t.text==='bool' || ['true','false'].includes(t.text) && body[i-1]?.text!=='return')) return false;
    const writes=new Map(), parameters=new Map(method.parameters.map(p=>[p.name,p.type]));
    for(let i=start+1;i<end;i++) if(ts[i].kind==='identifier' && ts[i+1]?.text==='=') {
      let limit=i+2;
      while(limit<end && ts[limit].text!==';') limit++;
      const key=name(ts[i]); if(!writes.has(key)) writes.set(key,[]);
      writes.get(key).push(ts.slice(i+2,limit));
    }
    let proofWork=0;
    function inputRead(key, visiting=new Set()) {
      if(++proofWork>10000 || visiting.has(key) || visiting.size>16) return false;
      if(parameters.has(key)) return !writes.has(key);
      const values=writes.get(key); if(!values?.length) return false;
      const next=new Set(visiting);next.add(key);
      return values.every(value=>value.some(t=>t.kind==='identifier' && inputRead(name(t),next)));
    }
    function condition(value,depth=0) {
      if(!value.length || depth>32) return false;
      if(value[0].text==='(' && pairs.get(ts.indexOf(value[0]))===ts.indexOf(value.at(-1))) return condition(value.slice(1,-1),depth+1);
      let nesting=0;
      for(let i=0;i<value.length;i++) {
        if(value[i].text==='(') nesting++;
        else if(value[i].text===')') nesting--;
        else if(!nesting && ['&&','||'].includes(value[i].text)) return condition(value.slice(0,i),depth+1)&&condition(value.slice(i+1),depth+1);
      }
      if(value[0].text==='!') return condition(value.slice(1),depth+1);
      const compare=value.findIndex(t=>['==','!='].includes(t.text));
      if(compare<0) return value.length===1 && parameters.get(name(value[0]))==='bool' && inputRead(name(value[0]));
      const left=value.slice(0,compare),right=value.slice(compare+1);
      const literal=part=>part.length===1 && (part[0].kind==='string'||part[0].text==='null');
      const read=part=>part.length%2===1 && part[0]?.kind==='identifier' && inputRead(name(part[0])) &&
        part.every((t,i)=>i===0 || (i%2===1 ? ['.','?.'].includes(t.text) : t.kind==='identifier'));
      return literal(left)&&read(right) || read(left)&&literal(right);
    }
    let operations=0, seen=0;
    function outcome(statement) {
      if(statement.length<6 || statement[0].text!=='Console' || statement[1].text!=='.' ||
          statement[2].text!=='WriteLine' || statement[3].text!=='(' || statement.at(-1).text!==')') return 0;
      const token=statement[4];
      if(!['string','interpolated-string'].includes(token.kind) || ![')',','].includes(statement[5]?.text)) return 0;
      // Interpolation expressions are opaque to the lexer. Admit only simple
      // member reads; never derive outcome words from an expression or format.
      let text=token.text;
      if(token.kind==='interpolated-string') {
        if(!/^\$"[^"\\]*"$/.test(text)) return 0;
        text=text.replace(/\{[A-Za-z_]\w*(?:\??\.[A-Za-z_]\w*)*\}/g,'');
        if(/[{}]/.test(text)) return 0;
      }
      if(!/\b(?:auth(?:entication|enticated)?|login|sign.in)\b/i.test(text)) return 0;
      let bits=0;
      if(/\b(?:success(?:ful(?:ly)?)?|succeeded)\b/i.test(text)) bits|=1;
      if(/\b(?:fail(?:ed|ure)?|denied|rejected)\b/i.test(text)) bits|=2;
      return bits===3 || /\b(?:not|never|missing|disabled|unrecorded)\b/i.test(text) ? 0 : bits;
    }
    // Each path carries observed success/failure bits. Returning terminates a
    // path; unreachable statements cannot contribute logging evidence.
    function sequence(begin,limit,states,depth) {
      if(depth>32) throw Error('depth');
      let i=begin, exits=[];
      while(i<limit) {
        if(++operations>10000) throw Error('budget');
        const result=statement(i,limit,states,depth+1);
        i=result.next; states=result.states; exits.push(...result.exits);
        states=[...new Set(states)]; exits=[...new Set(exits)];
      }
      return {states,exits};
    }
    function statement(i,limit,states,depth) {
      if(depth>32) throw Error('depth');
      if(ts[i].text==='{') {
        const close=pairs.get(i); if(close===undefined||close>=limit) throw Error('block');
        return {...sequence(i+1,close,states,depth+1),next:close+1};
      }
      if(ts[i].text==='if') {
        const close=pairs.get(i+1); if(ts[i+1]?.text!=='('||close===undefined) throw Error('condition');
        if(!condition(ts.slice(i+2,close))) throw Error('unsupported condition');
        const yes=statement(close+1,limit,states,depth+1);
        const no=ts[yes.next]?.text==='else'?statement(yes.next+1,limit,states,depth+1):{next:yes.next,states,exits:[]};
        return {next:no.next,states:[...yes.states,...no.states],exits:[...yes.exits,...no.exits]};
      }
      let end=i;
      while(end<limit&&ts[end].text!==';') {
        if(['(', '['].includes(ts[end].text)) { const close=pairs.get(end); if(close===undefined||close>=limit) throw Error('expression'); end=close; }
        else if(['{','}','else'].includes(ts[end].text)) throw Error('unsupported');
        end++;
      }
      if(end>=limit) throw Error('unterminated');
      const bits=outcome(ts.slice(i,end));
      if(states.length) seen|=bits;
      const nextStates=states.map(value=>value|bits);
      return ts[i].text==='return'?{next:end+1,states:[],exits:nextStates}:{next:end+1,states:nextStates,exits:[]};
    }
    try {
      const result=sequence(start+1,end,[0],0), paths=[...result.states,...result.exits];
      return seen===3 && paths.length>0 && paths.every(bits=>bits!==0);
    } catch { return false; }
  });
  if(!covered) return false;
  // Source-visible aliases and custom Console owners in other files also
  // affect binding. Missing/oversized context keeps the original warning.
  if(!context) return true;
  if(ownerCache.has(context)) return ownerCache.get(context);
  const files=context.files.filter(f=>f.lang==='csharp');
  if(context.complete!==true || files.length>1000 || files.reduce((sum,f)=>sum+f.code.length,0)>8*1024*1024) return false;
  const closed=files.every(file=>{
    const lexed=tokenizeCSharp(file.code);
    return file.code.length<=200000 && !lexed.errors.length && !lexed.regions.some(r=>r.kind==='directive') && ownersClosed(lexed.tokens);
  });
  ownerCache.set(context,closed);
  return closed;
}

module.exports={csharpConsoleAuthEvidence};
