'use strict';
const path=require('node:path').posix;
const {buildProofIndex,name,text,split}=require('./csharp-proof-index');

function createRazorModelFacts(sources,options={}){
 const index=buildProofIndex(sources,options),none=new Map();if(!index)return none;
 const views=sources.filter(s=>s.file.endsWith('.cshtml'));
 const reserved=new Set(['System','HtmlEncoder','JsonSerializer','Controller','ControllerBase','IHtmlHelper','IServiceCollection','WebApplicationBuilder']);
 if(index.files.some(f=>f.ts.some((t,i)=>['HtmlEncoder','JsonSerializer'].includes(name(t))&&f.ts[i+1]?.text!=='.')))return none;
 if(index.types.some(t=>reserved.has(t.name))||index.files.some(f=>f.ts.some((t,i)=>reserved.has(name(t))&&f.ts[i-1]?.text!=='.'&&f.ts[i-1]?.text!=='using'&&(['=',';','=>'].includes(f.ts[i+1]?.text)||f.ts[i+1]?.text==='{'&&name(f.ts[i-1])))))return none;
 if(index.types.some(t=>t.methods.some(m=>['View','Raw','Encode','Serialize','AddScoped','AddSingleton','AddTransient'].includes(m.name))))return none;
 if(index.files.some(f=>f.ts.some(t=>['GetType','GetProperty','GetField','SetValue','Invoke','Activator','IViewLocationExpander','IRazorViewEngine','IResultFilter','IAsyncResultFilter','ViewResult','ViewData','Replace','TryAddScoped','TryAddSingleton','TryAddTransient','Decorate'].includes(name(t)))))return none;
 if(index.files.some(f=>f.ts.some((t,i)=>['dynamic','ServiceDescriptor','IServiceCollection','ServiceCollection'].includes(name(t))||name(t)==='Services'&&(f.ts[i+1]?.text!=='.'||!['AddScoped','AddSingleton','AddTransient','AddControllersWithViews','AddAuthentication','AddAuthorization','GetRequiredService'].includes(name(f.ts[i+2]))))))return none;
 if(index.types.some(t=>t.methods.some(m=>['AddControllersWithViews','AddAuthentication','AddAuthorization','GetRequiredService'].includes(m.name))))return none;
 const registrations=new Map();
 for(const f of index.files)for(let i=0;i<f.ts.length;i++){
  const ts=f.ts;if(!['AddScoped','AddSingleton','AddTransient'].includes(name(ts[i])))continue;
  if(ts[i+1]?.text!=='<')return none;
  if(ts[i+3]?.text==='>'&&ts[i+4]?.text==='('&&ts[i+5]?.text===')'){
   const self=index.resolve(name(ts[i+2]),f);
   if(self?.kind==='interface'){if(!registrations.has(self.id))registrations.set(self.id,[]);registrations.get(self.id).push(null);}
   continue;
  }
  if(ts[i-1]?.text!=='.'||ts[i-2]?.text!=='Services'||ts[i+3]?.text!==','||ts[i+5]?.text!=='>'||ts[i+6]?.text!=='('||ts[i+7]?.text!==')')return none;
  const iface=index.resolve(name(ts[i+2]),f),impl=index.resolve(name(ts[i+4]),f);
  if(!iface)continue;
  const valid=impl&&iface.kind==='interface'&&impl.kind==='class'&&[':'+iface.name,':'+iface.id].includes(impl.header);
  if(!registrations.has(iface.id))registrations.set(iface.id,[]);registrations.get(iface.id).push(valid?impl:null);
 }
 const isString=(tokens,method)=>{
  if(tokens.length!==1)return false;
  if(tokens[0].kind==='string')return true;
  return method.parameters?.some(p=>p.type==='string'&&p.name===name(tokens[0]));
 };
 function producer(method){
  if(!method.public||!method.parameters||method.expression||!index.implicit(method.file))return null;
  let body=method.body,local=null;
  if(body[0]?.text==='var'&&name(body[1])&&body[2]?.text==='='){
   const semi=body.findIndex(t=>t.text===';');if(semi<0)return null;
   const expr=body.slice(3,semi),open=expr.findIndex(t=>t.text==='(');
   if(open!==3||expr[1]?.text!=='.'||expr.at(-1)?.text!==')')return null;
   const helper=index.resolve(name(expr[0]),method.file),methods=helper?.methods.filter(m=>m.name===name(expr[2]));
   if(methods?.length!==1||methods[0].prefix.at(-1)?.text!=='string'||!methods[0].prefix.some(t=>t.text==='static'))return null;
   if(index.files.some(f=>f.ts.some((t,i)=>name(t)===helper.name&&!['class','record','struct','interface'].includes(f.ts[i-1]?.text)&&f.ts[i+1]?.text!=='.')))return null;
   const args=split(expr.slice(open+1,-1));if(!args.length||!isString(args[0],method)||args.slice(1).some(p=>p.length!==1||!['number','string','true','false','null'].includes(p[0].kind)&&!['true','false','null'].includes(p[0].text)))return null;
   local=name(body[1]);body=body.slice(semi+1);
  }
  if(text(body.slice(0,2))!=='returnnew'||body[3]?.text!=='('||text(body.slice(-2))!==');')return null;
  const model=index.resolve(name(body[2]),method.file);
  if(!model||model.kind!=='record'||model.close!==model.open||model.primary?.length!==1||model.primary[0].type!=='string'||model.header!=='(string'+model.primary[0].name+')')return null;
  const value=body.slice(4,-2),stringValue=ts=>isString(ts,method)||ts.length===1&&name(ts[0])===local;
  let kind=null;
  if(text(value.slice(0,6))==='HtmlEncoder.Default.Encode('&&value.at(-1)?.text===')'&&stringValue(value.slice(6,-1))&&method.file.imports.includes('System.Text.Encodings.Web')&&index.framework(method.file,'HtmlEncoder','System.Text.Encodings.Web'))kind='html';
  if(text(value.slice(0,6))==='JsonSerializer.Serialize(new{'&&text(value.slice(-2))==='})'&&value[6]?.kind==='identifier'&&value[7]?.text==='='&&stringValue(value.slice(8,-2))&&method.file.imports.includes('System.Text.Json')&&index.framework(method.file,'JsonSerializer','System.Text.Json'))kind='json';
  // The anonymous object is restricted to a single statically string property;
  // options, converters, custom carriers and post-serialization edits decline.
  return kind?{kind,model:model.id,property:model.primary[0].name}:null;
 }
 const records=new Map();
 for(const f of index.files)for(let i=0;i<f.ts.length;i++){
  if(name(f.ts[i])!=='View'||f.ts[i+1]?.text!=='(')continue;
  const end=f.pairs.get(i+1);if(end===undefined)return none;
  const args=split(f.ts.slice(i+2,end));
  let viewName;try{viewName=JSON.parse(args[0]?.length===1&&args[0][0].kind==='string'?args[0][0].text:'null');}catch{return none;}
  if(typeof viewName!=='string'||!/^[A-Za-z_]\w*$/.test(viewName))return none;
  const projects=(options.projects||[]).filter(p=>f.file.startsWith(path.dirname(p.file)+'/')).sort((a,b)=>b.file.length-a.file.length);
  const root=projects[0]?path.dirname(projects[0].file):path.dirname(f.file);
  const candidates=views.filter(v=>v.file.startsWith(root+'/Views/')&&path.basename(v.file).toLowerCase()===(viewName+'.cshtml').toLowerCase());
  if(candidates.length!==1){for(const v of candidates)records.set(v.file,[null]);continue;}
  const view=candidates[0];if(!records.has(view.file))records.set(view.file,[]);
  let fact=null;
  const owners=index.types.filter(t=>t.file===f&&t.methods.some(m=>m.body.some(x=>x.start===f.ts[i].start)));
  if(owners.length===1){
   const owner=owners[0],method=owner.methods.find(m=>m.body.some(x=>x.start===f.ts[i].start));
   const body=method.expression?method.body:method.body[0]?.text==='return'&&method.body.at(-1)?.text===';'?method.body.slice(1,-1):[];
   const value=args[1];
   if(!owner.unsupported&&index.implicit(f)&&/:Controller(?:Base)?$/.test(owner.header)&&method.public&&body[0]?.start===f.ts[i].start&&body.at(-1)?.end===f.ts[end].end&&args.length===2&&value?.length===6&&value[1]?.text==='.'&&value[3]?.text==='('&&value.at(-1)?.text===')'&&method.parameters?.some(p=>p.type==='string'&&p.name===name(value[4]))){
    const receiver=owner.primary?.filter(p=>p.name===name(value[0]));
    const receiverName=name(value[0]);
    const writes=f.ts.slice(owner.open+1,owner.close).some((token,n,ts)=>name(token)===receiverName&&(ts[n+1]?.text!=='.'||ts[n-1]?.text==='.'||['ref','out'].includes(ts[n-1]?.text)));
    if(receiver?.length===1&&!writes&&!method.parameters.some(p=>p.name===receiverName)){
     const iface=index.resolve(receiver[0].type,f),targets=iface&&registrations.get(iface.id);
     if(targets?.length===1&&targets[0]&&!iface.header&&iface.primary?.length===0){
      const producers=targets[0].methods.filter(m=>m.name===name(value[2]));
      const signatures=split(iface.file.ts.slice(iface.open+1,iface.close),';');
      const declarations=signatures.at(-1)?.length===0?signatures.slice(0,-1):[];
      const valid=declarations.length&&declarations.every(s=>s.length===6&&name(s[0])&&name(s[1])&&text(s.slice(2,4))==='(string'&&name(s[4])&&s[5].text===')');
      const matches=declarations.filter(s=>name(s[1])===name(value[2]));
      const signature=matches[0];
      if(valid&&matches.length===1&&producers.length===1&&producers[0].parameters?.length===1&&producers[0].parameters[0].type==='string'){
       fact=producer(producers[0]);
       if(fact&&index.resolve(name(signature[0]),iface.file)?.id!==fact.model)fact=null;
      }
     }
    }
   }
  }
  records.get(view.file).push(fact);
 }
 const result=new Map();
 for(const [file,values]of records){
  if(values.length&&values.every(v=>v&&JSON.stringify(v)===JSON.stringify(values[0])))result.set(file,values[0]);
 }
 return result;
}
module.exports={createRazorModelFacts};
