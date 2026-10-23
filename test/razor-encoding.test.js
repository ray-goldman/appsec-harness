'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {scan}=require('../src/engine');
const encoded='@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description))';
async function hits(t,source,extra={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-razor-'));
 t.after(()=>{assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));assert.ok(path.basename(root).startsWith('kayfabe-razor-'));fs.rmSync(root,{recursive:true,force:true});});
 for(const [name,text]of Object.entries({'Views/Details.cshtml':source,...extra})){const dest=path.join(root,name);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,text);}
 return (await scan(root,{includeTests:true})).findings.filter(f=>f.ruleId==='CS-XSS-001');
}
test('Razor direct framework encoding is quiet only in supported HTML text',async t=>{
 for(const source of [encoded,`@model Product\n<div class="description">${encoded}</div>`,`<section>\n<p>${encoded}</p>\n</section>`,`<!-- static comment -->\n<div>${encoded}</div>`,`<div>${encoded} ${encoded}</div>`,`<h1>Details</h1>\n<div>${encoded}</div>`])
  assert.equal((await hits(t,source)).length,0,source);
 assert.equal((await hits(t,`<div>${encoded}</div>`,{'Other.cs':'using System; class Other {}'})).length,0);
 assert.equal((await hits(t,`<input disabled\n>\n<div>${encoded}</div>`)).length,0);
});
test('Razor raw input and encoding used in other output contexts retain warnings',async t=>{
 for(const source of ['<div>@Html.Raw(Model.Description)</div>',`<script>var text = ${encoded};</script>`,`<style>p { color: ${encoded}; }</style>`,`<div data-x=${encoded}>x</div>`,`<textarea>${encoded}</textarea>`,`<svg><text>${encoded}</text></svg>`,`<template>${encoded}</template>`,`<div>${encoded} @Html.Raw(Model.Other)</div>`])
  assert.ok((await hits(t,source)).length>0,source);
});
test('Razor proof does not borrow an encoder from another expression or line',async t=>{
 for(const source of [`<div>${encoded} @Html.Raw(Model.Other)</div>`,`<div>${encoded}\n@Html.Raw(Model.Other)</div>`,`<div>@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description) + Model.Other)</div>`,`<div>@Html.Raw(WebUtility.HtmlEncode(Model.Description))</div>`,`<div>@Html.Raw(Custom.HtmlEncode(Model.Description))</div>`,`<div>@Html.Raw(System.Net.WebUtility.HtmlDecode(Model.Description))</div>`,`<div>@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description)) @new HtmlString(Model.Other)</div>`])
  assert.ok((await hits(t,source)).length>0,source);
});
test('Razor unknown code, aliases and visible framework shadows retain warnings',async t=>{
 for(const [source,extra]of [
  [`@{ var System = custom; }\n<div>${encoded}</div>`,{}],
  [`@inject CustomHelper Html\n<div>${encoded}</div>`,{}],
  [`@inherits CustomView\n<div>${encoded}</div>`,{}],
  [`<div>${encoded}</div>`,{'Views/_ViewImports.cshtml':'@using System = Vendor.System'}],
  [`<div>${encoded}</div>`,{'Other.cs':'public class System {}'}],
  [`<div>${encoded}</div>`,{'Other.cs':'namespace System.Net { public class WebUtility {} }'}],
  [`<div>${encoded}</div>`,{'Other.cs':'public class CustomView { public CustomHelper Html { get; set; } }'}],
  [`<div>${encoded}</div>`,{'Views/_ViewImports.cshtml':'@addTagHelper *, CustomComponents'}],
  [`<div>${encoded}</div>`,{'Other.cs':'class C { object Get() { return PartialView("Details"); } }'}],
 ])assert.ok((await hits(t,source,extra)).length>0,source);
});
test('Razor malformed and unsupported markup never earns an encoding proof',async t=>{
 for(const source of [`<script>\n${encoded}`,`<div title="unterminated>\n${encoded}`,`<math><mtext>${encoded}</mtext></math>`,`<custom-element>${encoded}</custom-element>`,`<div><span></div>\n${encoded}`,`<script src="x"/>\n${encoded}`,`<noscript>${encoded}</noscript>`,`<plaintext>\n${encoded}`])
  assert.ok((await hits(t,source)).length>0,source);
});
test('Razor refinement preserves the neighboring unencoded and script-context findings',async t=>{
 const source=`@model Product\n<div>@Html.Raw(Model.Description)</div>\n<div>${encoded}</div>\n<script>var text = ${encoded};</script>`;
 assert.deepEqual((await hits(t,source)).map(f=>f.line),[2,3,4]);
 assert.ok((await hits(t,`class C { void Render() { Html.Raw(System.Net.WebUtility.HtmlEncode(value)); } }`,{'Other.cs':'class Other {}'})).length>0);
});
test('Razor review regressions retain uncertain preceding output, HTML recovery and layout contexts',async t=>{
 for(const source of [`@Html.Raw(Model.OpenMarkup)\n${encoded}`,`@Html.Raw("<script>")\n${encoded}`,`@Html.Partial("StartScript")\n${encoded}`,`@Model.OpenMarkup\n${encoded}`,`<script></scriptx>\n${encoded}`,`<div a=x" ><script> ">\n${encoded}\n</div>`,`<!-- --!><script> -->\n${encoded}`,`<!--><script> -->\n${encoded}`,`<!-- @Html.Raw(Model.OpenMarkup) -->\n${encoded}`,`<script><!--<script></script>\n${encoded}\n<!-- </script> -->`]){
  const got=await hits(t,source);assert.ok(got.some(f=>f.line===source.slice(0,source.indexOf(encoded)).split('\n').length),source);
 }
 assert.ok((await hits(t,encoded,{'Views/_ViewStart.cshtml':'@{ Layout = "_Layout"; }','Views/Shared/_Layout.cshtml':'<script>@RenderBody()</script>'})).length>0);
});

test('Razor proof never refines quoted attributes or JavaScript strings even when the baseline misses them',()=>{
 const {createRazorEncodingProof}=require('../src/razor-encoding');
 for(const raw of [`<script>var x = '${encoded}';</script>`,`<a href="${encoded}">link</a>`,`<div title='${encoded}'>x</div>`])
  assert.equal(createRazorEncodingProof([{file:'Views/A.cshtml',raw}])('Views/A.cshtml',1),false,raw);
});
test('Razor proof declines incomplete source and explicit analysis limits',()=>{
 const {createRazorEncodingProof}=require('../src/razor-encoding');
 const one={file:'Views/A.cshtml',raw:`<div>${encoded}</div>`};
 assert.equal(createRazorEncodingProof([one])(one.file,1),true);
 assert.equal(createRazorEncodingProof([one],{complete:false})(one.file,1),false);
 for(const raw of [one.raw+' '.repeat(100001),'<div>'.repeat(65)+encoded+'</div>'.repeat(65),('<div>'+encoded+'</div>\n').repeat(257),one.raw+'\0'])
  assert.equal(createRazorEncodingProof([{...one,raw}])(one.file,1),false);
 assert.equal(createRazorEncodingProof([one,...Array.from({length:1000},(_,i)=>({file:`Other${i}.cs`,raw:'class Other {}'}))])(one.file,1),false);
 assert.equal(createRazorEncodingProof([one,{file:'Other.cs',raw:';'.repeat(20001)}])(one.file,1),false);
});
