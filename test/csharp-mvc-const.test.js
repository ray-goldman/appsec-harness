'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {scan}=require('../src/engine');
const project='<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>';
const constants='namespace Example.Data; public class QueryText { public const string Columns="id, name"; }';
const consumer=(expression='$"SELECT {QueryText.Columns} FROM records WHERE id=$id"',base='ControllerBase')=>`using Microsoft.AspNetCore.Mvc;
using Example.Data;
namespace Example.Web;
public class Reports : ${base} {
 public void Run(dynamic command,string input) {
  command.CommandText = ${expression};
 }
}`;
async function sql(t,files={}) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-mvc-const-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 for(const [file,raw]of Object.entries({'Example.csproj':project,'Data/QueryText.cs':constants,'Reports.cs':consumer(),...files})){
  const dest=path.join(root,file);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,raw);
 }
 return (await scan(root)).findings.filter(f=>f.ruleId==='CS-SQLI-001');
}
for(const base of ['ControllerBase','Microsoft.AspNetCore.Mvc.ControllerBase','global::Microsoft.AspNetCore.Mvc.ControllerBase'])
test(`literal const interpolation in a modeled ${base} consumer is safe`,async t=>{
 assert.equal((await sql(t,{'Reports.cs':consumer(undefined,base)})).length,0);
});
test('modeled MVC raw interpolation retains SQL parameter placeholders',async t=>{
 assert.equal((await sql(t,{'Reports.cs':consumer('$"""\nSELECT {QueryText.Columns}\nFROM records WHERE id=$id\n"""')})).length,0);
});
test('a modeled MVC base does not sanitize request interpolation',async t=>{
 assert.ok((await sql(t,{'Reports.cs':consumer('$"SELECT {QueryText.Columns} FROM records WHERE name={input}"')})).length);
});
for(const [label,files]of Object.entries({
 'unknown target':{'Example.csproj':project.replace('net10.0','net11.0')},
 'older unmodeled target':{'Example.csproj':project.replace('net10.0','net8.0')},
 'non-web SDK':{'Example.csproj':project.replace('Microsoft.NET.Sdk.Web','Microsoft.NET.Sdk')},
 'custom framework override':{'Example.csproj':project.replace('</PropertyGroup>','<RuntimeFrameworkVersion>10.0.1</RuntimeFrameworkVersion></PropertyGroup>')},
 'multi-targeting':{'Example.csproj':project.replace('<TargetFramework>net10.0</TargetFramework>','<TargetFrameworks>net10.0;net8.0</TargetFrameworks>')},
 'unknown inherited class':{'Reports.cs':consumer(undefined,'UnknownController')},
 'Controller view inheritance':{'Reports.cs':consumer(undefined,'Controller')},
 'additional interface':{'Reports.cs':consumer(undefined,'ControllerBase, IExtra'),'Extra.cs':'namespace Example.Web; public interface IExtra {}'},
 'source framework look-alike':{'Base.cs':'namespace Microsoft.AspNetCore.Mvc; public class ControllerBase {}'},
 'unimported base interface decoy':{'Base.cs':'namespace Other; public interface ControllerBase {}'},
 'namespace type collision':{'Other.cs':'public class Microsoft {}'},
 'owner member shadow':{'Reports.cs':consumer().replace('public void Run','public dynamic QueryText;\n public void Run')},
 'parameter shadow':{'Reports.cs':consumer().replace('string input','string input,dynamic QueryText')},
 'mutable source field':{'Data/QueryText.cs':constants.replace('const string','static string')},
 'readonly source field':{'Data/QueryText.cs':constants.replace('const string','static readonly string')},
 'alias binding':{'Alias.cs':'using ControllerBase = Other.Base;'},
 'source subclass':{'Reports.cs':consumer(undefined,'CustomBase'),'Base.cs':'using Microsoft.AspNetCore.Mvc; namespace Example.Web; public class CustomBase : ControllerBase {}'},
 'partial consumer':{'Reports.cs':consumer().replace('class Reports','partial class Reports')},
 'dynamic SQL suffix':{'Reports.cs':consumer('$"SELECT {QueryText.Columns}" + input')},
})) test(`retains SQL warning for ${label}`,async t=>{assert.ok((await sql(t,files)).length);});

for(const [receiver,member]of [['Request','Method'],['HttpContext','TraceIdentifier'],['User','Identity'],['Url','ActionContext'],['ControllerContext','ActionDescriptor'],['RouteData','Values'],['ModelState','ErrorCount'],['Response','ContentType']])
test(`inherited ${receiver} cannot bind an imported const type`,async t=>{
 const source=consumer(`$"SELECT {${receiver}.${member}} FROM records"`);
 assert.ok((await sql(t,{'Reports.cs':source,'Decoy.cs':`namespace Example.Data; public class ${receiver} { public const string ${member}="id"; }`})).length);
});

test('every name in the pinned framework closure prevents const receiver binding',()=>{
 const {createMvcConstOwnerProof}=require('../src/csharp-mvc-binding');
 const profile=require('../src/frameworks/aspnetcore-controllerbase-net10.json');
 assert.equal(profile.schema,'kayfabe-framework-binding@1');assert.equal(profile.inheritedNames.length,67);
 assert.equal(new Set(profile.inheritedNames).size,profile.inheritedNames.length);
 for(const source of profile.sources){assert.match(source.url,/\/([a-f0-9]{40})\//);assert.match(source.sha256,/^[a-f0-9]{64}$/);}
 const owner={header:[{text:':'},{text:'ControllerBase'}],file:{namespace:'Example.Web',imports:['Microsoft.AspNetCore.Mvc']}};
 const proof=createMvcConstOwnerProof([{file:'Example.csproj',raw:project}],[]);
 assert.equal(proof(owner,[{type:'QueryText',member:'Columns'}]),true);
 for(const type of profile.inheritedNames)assert.equal(proof(owner,[{type,member:'Columns'}]),false,type);
});
