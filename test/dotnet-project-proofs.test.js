'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {scan}=require('../src/engine');
const project='<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>';
async function run(t,files,rule){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-proofs-'));
 t.after(()=>{assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));assert.ok(path.basename(root).startsWith('kayfabe-proofs-'));fs.rmSync(root,{recursive:true,force:true});});
 for(const [file,text]of Object.entries({'App/App.csproj':project,...files})){const dest=path.join(root,file);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,text);}
 return(await scan(root,{includeTests:true})).findings.filter(f=>f.ruleId===rule);
}
const command=body=>`using System.Diagnostics; namespace Example; class Jobs { public void Send(string input) {\n${body.replaceAll(';',';\n')}\n} }`;
const map='var choices = new Dictionary<string,string>(StringComparer.Ordinal) { ["alpha"] = "alpha", ["beta"] = "beta" };';
const guard='if (!choices.TryGetValue(input, out var selected)) throw new ArgumentException("Unknown job");';
const sink='var p = new ProcessStartInfo(); p.Arguments = "/c echo " + selected; Process.Start(p);';
test('closed local dictionary values reach a command only after a terminating failed lookup',async t=>{
 assert.equal((await run(t,{'App/Jobs.cs':command(map+guard+sink)},'CS-CMDI-001')).length,0);
});
test('dictionary proofs reject mutations, aliases, dynamic values and nonterminating lookup failure',async t=>{
 for(const body of [
  map+guard+'selected = input;'+sink,
  map+'var alias = choices; alias["alpha"] = input;'+guard+sink,
  map.replace('["alpha"] = "alpha"','["alpha"] = input')+guard+sink,
  map+guard.replace('throw new ArgumentException("Unknown job")','Log("missing")')+sink,
  map+guard+'Change(ref selected);'+sink,
  map+'choices["alpha"] = input;'+guard+sink,
  map+guard+'p.Arguments = "/c echo " + input;'+sink,
  map+guard+'if (condition) { selected = input; }'+sink,
 ])assert.ok((await run(t,{'App/Jobs.cs':command(body)},'CS-CMDI-001')).length>0,body);
});
test('dictionary identity shadows and unavailable project imports retain warnings',async t=>{
 for(const extra of [{'App/Other.cs':'class Dictionary<K,V> {}'},{'App/Other.cs':'global using Dictionary = Vendor.Map;'}, {'App/App.csproj':project.replace('</Project>','<ItemGroup><Using Include="Vendor" /></ItemGroup></Project>')}, {'App/Jobs.cs':command(map+guard+sink).replace('namespace Example;','using Vendor; namespace Example;')}])
  assert.ok((await run(t,{'App/Jobs.cs':command(map+guard+sink),...extra},'CS-CMDI-001')).length>0);
});
test('opaque expressions and escaped identifiers cannot hide command mutations',async t=>{
 for(const mutation of [String.raw`\u0073elected = input;`,'var ignored = $"{selected = input}";'])
  assert.ok((await run(t,{'App/Jobs.cs':command(map+guard+mutation+sink)},'CS-CMDI-001')).length>0);
});
test('an explicit dictionary import cannot bypass an unknown compile inclusion',async t=>{
 const files={'App/Jobs.cs':'using System.Collections.Generic; '+command(map+guard+sink),'App/App.csproj':project.replace('</Project>','<ItemGroup><Compile Include="../../external.cs" /></ItemGroup></Project>')};
 assert.ok((await run(t,files,'CS-CMDI-001')).length>0);
});
function rendering(kind='html'){
 const encode=kind==='html'?'HtmlEncoder.Default.Encode(value)':'JsonSerializer.Serialize(new { text = value })';
 return{
  'App/Program.cs':'using Example; builder.Services.AddScoped<IPresenter, Presenter>();',
  'App/Presenter.cs':`using System.Text.Encodings.Web; using System.Text.Json; namespace Example; public sealed record Card(string Text); public interface IPresenter { Card Build(string value); } public sealed class Presenter : IPresenter { public Card Build(string value) { return new Card(${encode}); } }`,
  'App/Controller.cs':'using Microsoft.AspNetCore.Mvc; namespace Example; public sealed class NotesController(IPresenter presenter) : Controller { [HttpGet("preview")] public IActionResult Preview(string value) => View("Preview", presenter.Build(value)); }',
  'App/Views/Shared/Preview.cshtml':`@model Example.Card\n<!doctype html><html><head><title>Preview</title></head><body>${kind==='html'?'<article>@Html.Raw(Model.Text)</article>':'<script>window.card = @Html.Raw(Model.Text);</script>'}</body></html>`
 };
}
test('a unique service producer encodes a string record for standalone HTML text',async t=>{
 assert.equal((await run(t,rendering(),'CS-XSS-001')).length,0);
 assert.equal((await run(t,{...rendering(),'App/Other.cs':'class Other { public void Close() { using var handle = Open(); } }'},'CS-XSS-001')).length,0);
 assert.equal((await run(t,{...rendering(),'App/Book.cs':'namespace Example; public class Book {}','App/Program.cs':rendering()['App/Program.cs']+' builder.Services.AddSingleton<Book>();'},'CS-XSS-001')).length,0);
 assert.equal((await run(t,{...rendering(),'App/Other.cs':'using System.Reflection; class Other { public string Location() => Assembly.GetExecutingAssembly().Location; }'},'CS-XSS-001')).length,0);
 assert.equal((await run(t,{...rendering(),'App/Other.cs':'class Other { public object Folder() { return Environment.SpecialFolder.System; } }'},'CS-XSS-001')).length,0);
 assert.equal((await run(t,{...rendering(),'App/Other.cs':'class Other { public string Url() { var port = int.Parse("5080"); return $"http://127.0.0.1:{port}"; } }'},'CS-XSS-001')).length,0);
});
test('a unique service producer serializes a string object for an unquoted script expression',async t=>{
 assert.equal((await run(t,rendering('json'),'CS-XSS-001')).length,0);
});
test('producer/model/view mutations and ambiguous producers retain warnings',async t=>{
 const changes=[
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('public Card Build(string value)', 'Card IPresenter.Build(string value) => new Card(value); public Card Build(string value)'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('public Card Build(string value)', 'private static dynamic HtmlEncoder => new { Default = new { Encode = (Func<string,string>)(x => x) } }; public Card Build(string value)'),
  f=>f['App/App.csproj']=project.replace('</Project>','<ItemGroup><Compile Remove="Presenter.cs" /><Compile Include="../../external-producer.cs" /></ItemGroup></Project>'),
  f=>f['App/Controller.cs']=f['App/Controller.cs'].replace('public IActionResult Preview','public void Swap() { var ignored = $"{presenter = new UnsafePresenter()}"; } public IActionResult Preview'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('HtmlEncoder.Default.Encode(value)','value'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('Card Build(string value);','Card Build(object value) => new Card(value.ToString());'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('interface IPresenter {','interface IPresenter : IAlternate {'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('public Card Build','private FakeEncoder HtmlEncoder, ignored; public Card Build'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('HtmlEncoder.Default.Encode(value)','HtmlEncoder.Default.Encode(value) + value'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('public sealed record Card(string Text);','public record Card(string Text) { public string Other => Text; }'),
  f=>f['App/Controller.cs']=f['App/Controller.cs'].replace('presenter.Build(value)','new Card(value)'),
  f=>f['App/Controller.cs']+=' class Other : Controller { public IActionResult X(string value) => View("Preview", new Card(value)); }',
  f=>f['App/Controller.cs']+=' class Other : Controller { public IActionResult X(string name, object value) => View(name, value); }',
  f=>f['App/Program.cs']+=' builder.Services.AddScoped<IPresenter, OtherPresenter>();',
  f=>f['App/Program.cs']+=' builder.Services.Add(ServiceDescriptor.Scoped<IPresenter, UnsafePresenter>());',
  f=>f['App/Program.cs']+=' builder.Services[0] = ServiceDescriptor.Scoped<IPresenter, UnsafePresenter>();',
  f=>f['App/Program.cs']+=' builder.Services.Replace(ServiceDescriptor.Scoped<IPresenter, OtherPresenter>());',
  f=>f['App/Controller.cs']=f['App/Controller.cs'].replace('public IActionResult Preview','public void Swap(IPresenter next) { presenter = next; } public IActionResult Preview'),
  f=>f['App/Controller.cs']=f['App/Controller.cs'].replace('public IActionResult Preview','public void Swap(IPresenter next) { int ignored; (presenter, ignored) = (next, 0); } public IActionResult Preview'),
  f=>f['App/Controller.cs']=f['App/Controller.cs'].replace('Preview(string value)','Preview(string value, IPresenter presenter)'),
  f=>{f['App/Controller.cs']=f['App/Controller.cs'].replace('sealed class','sealed partial class');f['App/Other.cs']='namespace Example; public sealed partial class NotesController { public void Swap(IPresenter next) { presenter = next; } }';},
  f=>f['App/Other.cs']='class Filter : IResultFilter { public void OnResultExecuting(ResultExecutingContext context) { ((ViewResult)context.Result).Model = Unknown(); } }',
  f=>f['App/Directory.Build.props']='<Project><ItemGroup><Using Include="Vendor" /></ItemGroup></Project>',
  f=>f['App/Directory.Build.props']=Buffer.concat([Buffer.from([0xff,0xfe]),Buffer.from('<Project><ItemGroup><Using Include="Vendor" /></ItemGroup></Project>','utf16le')]),
  f=>f['App/Other.cs']='using System.Text.Encodings.Web; class HtmlEncoder { }',
  f=>f['App/Views/Shared/_Layout.cshtml']='<script>@RenderBody()</script>',
 ];
 for(const [i,change]of changes.entries())await t.test('producer control '+i,async t=>{const files=rendering();change(files);assert.ok((await run(t,files,'CS-XSS-001')).length>0,String(change));});
});
test('a string-valued local helper is not inferred from an attribute mentioning string',async t=>{
 const files=rendering('json');
 files['App/Presenter.cs']=files['App/Presenter.cs'].replace('return new Card','var selected = Values.Read(value); return new Card').replace('text = value','text = selected');
 files['App/Values.cs']='namespace Example; class Values { [Hint(typeof(string))] public static object Read(string value) { return GetCustomConvertedObject(value); } }';
 assert.ok((await run(t,files,'CS-XSS-001')).length>0);
});
test('a helper type name cannot be shadowed by an instance field',async t=>{
 const files=rendering('json');
 files['App/Presenter.cs']=files['App/Presenter.cs'].replace('public Card Build','private dynamic Values = new EvilValues(); public Card Build').replace('return new Card','var selected = Values.Read(value); return new Card').replace('text = value','text = selected');
 files['App/Values.cs']='namespace Example; class Values { public static string Read(string value) { return value; } }';
 assert.ok((await run(t,files,'CS-XSS-001')).length>0);
});
test('JSON producer proof rejects options, converters, extra values and quoted script contexts',async t=>{
 for(const change of [
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('Serialize(new { text = value })','Serialize(new { text = value }, options)'),
  f=>f['App/Presenter.cs']=f['App/Presenter.cs'].replace('Serialize(new { text = value })','Serialize(value) + value'),
  f=>f['App/Other.cs']='class JsonSerializer { public static string Serialize(object value) => value.ToString(); }',
  f=>f['App/Other.cs']='global using JsonSerializer = Vendor.Serializer;',
  f=>f['App/Views/Shared/Preview.cshtml']=f['App/Views/Shared/Preview.cshtml'].replace('<script>','<script><!--<script>'),
 ]){const files=rendering('json');change(files);assert.ok((await run(t,files,'CS-XSS-001')).length>0,String(change));}
});
test('quoted script expressions never gain a proof even when generic masking misses their warning',()=>{
 const {createRazorEncodingProof}=require('../src/razor-encoding');
 const files=rendering('json');
 files['App/Views/Shared/Preview.cshtml']=files['App/Views/Shared/Preview.cshtml'].replace('window.card = ','window.card = "').replace(';</script>','";</script>');
 const sources=Object.entries(files).map(([file,raw])=>({file,raw}));
 assert.equal(createRazorEncodingProof(sources)('App/Views/Shared/Preview.cshtml',2),false);
 const attrs=rendering();attrs['App/Views/Shared/Preview.cshtml']=attrs['App/Views/Shared/Preview.cshtml'].replace('<article>','<article title="').replace('</article>','">text</article>');
 assert.equal(createRazorEncodingProof(Object.entries(attrs).map(([file,raw])=>({file,raw})))('App/Views/Shared/Preview.cshtml',2),false);
});
