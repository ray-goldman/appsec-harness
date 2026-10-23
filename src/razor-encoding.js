'use strict';
const {tokenizeCSharp}=require('./parsers/csharp/lexer');
const id=t=>t?.kind==='identifier'?t.text.replace(/^@/,''):null;
const TEXT_TAGS=new Set('html head body div span p section article header footer main aside h1 h2 h3 h4 h5 h6 ul ol li dl dt dd strong em b i u s pre code a label button form'.split(' '));
const VOID_TAGS=new Set(['br','hr','input','meta','link']);
const RAW_TAGS=new Set('script style textarea title xmp iframe noembed noframes noscript plaintext'.split(' '));

// Razor expressions are opaque to the static HTML context tracker. Only
// single-line, balanced identifier/member calls are admitted here.
function atom(raw,start) {
  let end=raw.indexOf('\n',start);if(end<0)end=raw.length;
  if(end-start>4096)return null;
  const lex=tokenizeCSharp(raw.slice(start+1,end)),ts=lex.tokens;
  if(!id(ts[0]))return null;
  let i=1;while(ts[i]?.text==='.'&&id(ts[i+1]))i+=2;
  const head=ts.slice(0,i).map(t=>t.text).join('');
  if(['if','else','for','foreach','while','do','switch','try','functions','inject','inherits','namespace','addTagHelper','removeTagHelper','tagHelperPrefix','section','await','using','model','page','layout','implements','attribute','code','helper','lock'].includes(ts[0].text))return null;
  if(ts[i]?.text==='('){
    let depth=0,j=i;
    for(;j<ts.length;j++){
      if(ts[j].text==='(')depth++;
      else if(ts[j].text===')'&&!--depth)break;
      else if(['{','}','[',']',';','=>'].includes(ts[j].text))return null;
    }
    if(j===ts.length)return null;i=j+1;
  }
  const stop=ts[i-1].end;
  if(lex.errors.some(e=>e.start<stop))return null;
  if(['.','[','?','!'].includes(raw[start+1+stop]))return null;
  return {end:start+1+stop,head,tokens:ts.slice(0,i)};
}
function encoded(a) {
  const ts=a.tokens;
  if(a.head!=='Html.Raw')return false;
  const prefix=['Html','.','Raw','(','System','.','Net','.','WebUtility','.','HtmlEncode','('];
  if(!prefix.every((v,i)=>ts[i]?.text===v)||ts.at(-1)?.text!==')'||ts.at(-2)?.text!==')')return false;
  const value=ts.slice(prefix.length,-2);
  // No concatenation, custom formatting, callbacks, nested calls or writer overload.
  return value.length>0&&value.length<=15&&value.every((t,i)=>i%2===0?!!id(t):t.text==='.')&&value.length%2===1;
}
function viewProof(raw) {
  const empty=new Set(),safe=new Set(),seen=new Map(),stack=[];
  if(raw.length>100000||raw.includes('\0'))return empty;
  let i=0,line=1,calls=0;
  const advance=end=>{for(let p=i;p<end;p++)if(raw[p]==='\n')line++;i=end;};
  function razor(){
    if(raw.startsWith('@@',i)){advance(i+2);return true;}
    if(raw.startsWith('@*',i)){const end=raw.indexOf('*@',i+2);if(end<0)return false;advance(end+2);return true;}
    // Only literal model and namespace imports, occupying their own line.
    const lineEnd=raw.indexOf('\n',i),stop=lineEnd<0?raw.length:lineEnd;
    if(/^\s*$/.test(raw.slice(raw.lastIndexOf('\n',i-1)+1,i))&&/^@(?:model|using)\s+[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\r?$/.test(raw.slice(i,stop))){advance(stop);return true;}
    const a=atom(raw,i);if(!a||++calls>256)return false;
    // Other Razor output can be IHtmlContent (including model properties),
    // partials or raw HTML that changes the following browser context.
    if(!encoded(a))return false;
    if(a.head==='Html.Raw'){
      const record=seen.get(line)||{count:0,safe:0};record.count++;record.safe++;seen.set(line,record);
    }
    advance(a.end);return true;
  }
  while(i<raw.length){
    if(raw[i]==='@'){if(!razor())return empty;continue;}
    if(raw.startsWith('<!--',i)){
      const end=raw.indexOf('-->',i+4);if(end<0)return empty;
      const body=raw.slice(i+4,end);
      if(body.includes('--')||body.includes('@')||body.startsWith('>')||body.startsWith('->')||body.includes('<!'))return empty;
      advance(end+3);continue;
    }
    if(raw[i]!=='<'){advance(i+1);continue;}
    const doctype=raw.slice(i,i+16).match(/^<!doctype html>/i);if(doctype){advance(i+doctype[0].length);continue;}
    const tag=raw.slice(i).match(/^<(\/?)([A-Za-z][A-Za-z0-9]*)\b/);if(!tag)return empty;
    const closing=!!tag[1],name=tag[2].toLowerCase();
    // Script escaped/double-escaped states and other raw-text parsing require
    // a full HTML tokenizer. None of those elements are admitted by this proof.
    if(RAW_TAGS.has(name)||!TEXT_TAGS.has(name)&&!VOID_TAGS.has(name))return empty;
    if(closing){
      const end=raw.slice(i).match(/^<\/[A-Za-z][A-Za-z0-9]*\s*>/);if(!end||stack.pop()!==name)return empty;
      advance(i+end[0].length);continue;
    }
    advance(i+tag[0].length);let closed=false,selfClosing=false;
    while(i<raw.length){
      if(raw[i]==='>'){closed=true;advance(i+1);break;}
      if(raw.startsWith('/>',i)){selfClosing=true;closed=true;advance(i+2);break;}
      if(!/\s/.test(raw[i]))return empty;
      while(i<raw.length&&/\s/.test(raw[i]))advance(i+1);
      if(raw[i]==='>'||raw.startsWith('/>',i))continue;
      const attribute=raw.slice(i).match(/^[A-Za-z_:][A-Za-z0-9_.:-]*/);if(!attribute)return empty;
      advance(i+attribute[0].length);
      let afterSpace=i;while(afterSpace<raw.length&&/\s/.test(raw[afterSpace]))afterSpace++;
      if(raw[afterSpace]!=='=')continue;
      advance(afterSpace+1);while(i<raw.length&&/\s/.test(raw[i]))advance(i+1);
      const quote=raw[i];if(quote!=='"'&&quote!=="'")return empty;
      advance(i+1);
      while(i<raw.length&&raw[i]!==quote){if(raw[i]==='@'||raw[i]==='<')return empty;advance(i+1);}
      if(raw[i]!==quote)return empty;advance(i+1);
    }
    if(!closed)return empty;
    if(!VOID_TAGS.has(name)){
      if(selfClosing)return empty; // HTML ignores slash on non-void elements.
      if(stack.length>=64)return empty;stack.push(name);
    }
  }
  if(stack.length)return empty;
  const lines=raw.split(/\r?\n/);
  for(const [line,record]of seen){
    if(record.count!==record.safe)continue;
    const text=lines[line-1];
    // The existing scanner reports at line granularity: every matching raw
    // output on that line must qualify, including other HtmlString sinks.
    const all=[...text.matchAll(/\bHtml\s*\.\s*Raw\s*\(|\bnew\s+HtmlString\s*\(/g)];
    if(all.length===record.count)safe.add(line);
  }
  return safe;
}
function createRazorEncodingProof(sources,{complete=true}={}) {
  const proofs=new Map(),none=()=>false;
  if(!complete||sources.length>1000||sources.reduce((n,s)=>n+Buffer.byteLength(s.raw),0)>8*1024*1024)return none;
  if(!sources.some(s=>/\.cshtml$/i.test(s.file)))return none;
  for(const s of sources){
    if(s.raw.length>100000)return none;
    if(/\.cshtml$/i.test(s.file)){
      if(/(?:^|[\\/])_(?:ViewStart|Layout)\b/i.test(s.file)||/\b(?:Layout|RenderBody|RenderSection|Partial|PartialAsync|RenderPartial|RenderPartialAsync)\b/.test(s.raw))return none;
      if(/@(?:inject|inherits|functions|namespace|addTagHelper|removeTagHelper|tagHelperPrefix)\b|@using\s+[^\r\n]*=/.test(s.raw))return none;
    }else{
      const lex=tokenizeCSharp(s.raw),ts=lex.tokens;
      if(lex.errors.length||ts.length>20000||lex.regions.some(r=>r.kind==='directive')||ts.some(t=>t.kind==='punctuation'&&/[^\x00-\x7f]|\\/.test(t.text)))return none;
      if(ts.some(t=>['PartialView','RenderBody','RenderSection','RenderAsync','IRazorViewEngine','ViewLocationExpanders','Layout','IHtmlHelper','IHtmlHelperFactory','HtmlHelper','Raw'].includes(id(t))))return none;
      if(ts.some((t,i)=>['System','WebUtility','Html'].includes(id(t))&&!(id(t)==='System'&&ts[i-1]?.text==='using'&&ts[i+1]?.text===';')&&(ts[i+1]?.text!=='.'||ts[i-1]?.text==='namespace'))||
         ts.some((t,i)=>id(t)==='HtmlEncode'&&ts[i-1]?.text!=='.'))return none;
    }
  }
  for(const s of sources)if(/\.cshtml$/i.test(s.file)&&s.raw.includes('Html.Raw'))proofs.set(s.file,viewProof(s.raw));
  return (file,line)=>proofs.get(file)?.has(line)||false;
}
module.exports={createRazorEncodingProof};
