'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {scan}=require('../src/engine');
async function findings(t,source,extra={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-py-values-'));
 t.after(()=>{assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
 for(const [name,text]of Object.entries({'app.py':source,...extra})){fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});fs.writeFileSync(path.join(root,name),text);}
 return(await scan(root,{includeTests:true})).findings;
}
const imports='from flask import Flask, request, render_template\napp = Flask(__name__)\n';
const sql=`def index():
    key = request.args.get("sort", "price")
    choices = {"price": "price ASC", "size": "size DESC"}
    order = choices.get(key, "price ASC")
    query = f"SELECT * FROM listings ORDER BY {order}"
    cursor.execute(query)
`;
const template='{{ badge | safe }}';
const html=`def index():
    badge = ""
    if request.args.get("kind") == "gold":
        badge = "<b>Gold</b>"
    else:
        badge = "<b>Standard</b>"
    return render_template("index.html", badge=badge)
`;
const sqlHits=fs=>fs.filter(f=>/^PY-SQLI-00[123]$/.test(f.ruleId));
const htmlHits=fs=>fs.filter(f=>f.ruleId==='TPL-XSS-001');
test('Python SQL literal local maps with a literal fallback are bounded choices',async t=>{
 for(const source of [sql,sql.replace('choices = {"price": "price ASC", "size": "size DESC"}','choices = {\n        "price": "price ASC",\n        "size": "size DESC",\n    }'),sql.replace('    choices','    if key:\n        choices').replace(/^    (order|query|cursor)/gm,'        $1')])
  assert.equal(sqlHits(await findings(t,imports+source)).length,0,source);
});
test('Python SQL retains unsafe map defaults, mutations, escapes and formatting expressions',async t=>{
 const variants=[
  sql.replace('choices.get(key, "price ASC")','choices.get(key, key)'),
  sql.replace('"size": "size DESC"','"size": key'),
  sql.replace('    order =','    choices[key] = key\n    order ='),
  sql.replace('    query =','    choices.update({key: key})\n    query ='),
  sql.replace('    order =','    mutate(choices)\n    order ='),
  sql.replace('    order =','    alias = choices\n    order ='),
  sql.replace('    order =','    choices = request.json\n    order ='),
  sql.replace('    query =','    order = key\n    query ='),
  sql.replace('{order}',"{order} {key}"),
  sql.replace('{order}',"{order!s}"),
  sql.replace('{order}',"{order:{key}}"),
  sql.replace('    cursor.execute(query)','    cursor.execute(query)\n    choices[key] = key'),
  sql.replace('    cursor.execute(query)','    cursor.execute(query)\n    f"{choices.update({key: key})}"'),
  sql.replace('    cursor.execute(query)','    f"{(ｑｕｅｒｙ := request.args.get(\'sql\'))}"\n    cursor.execute(query)'),
  sql.replace('def index():','def index(choices):'),
  sql.replace('    choices =','    global choices\n    choices ='),
  sql.replace('    choices =','    if key:\n        choices ='),
  sql.replace('    order =','    for choices in values:\n        pass\n    order ='),
  sql.replace('    order =','    with manager() as choices:\n        pass\n    order ='),
  sql.replace('    order =','    del choices\n    order ='),
  sql.replace('    order =','    exec(code)\n    order ='),
  sql.replace('cursor.execute(query)','cursor.execute(query) + cursor.execute(f"SELECT * FROM listings WHERE name = {key}")'),
  sql.replace('cursor.execute(query)','cursor.execute(query, cursor.execute(f"SELECT * FROM listings WHERE name = {key}"))'),
 ];
 for(const source of variants)assert.ok(sqlHits(await findings(t,imports+source)).length,source);
});
test('Python template literal branches retain no user-controlled markup',async t=>{
 assert.equal(htmlHits(await findings(t,imports+html,{'templates/index.html':template})).length,0);
 assert.equal(htmlHits(await findings(t,imports+html.replace('<b>Gold</b>','<b>Góld — 金</b>'),{'templates/index.html':template})).length,0);
 assert.equal(htmlHits(await findings(t,imports+html+'\ndef other():\n    return render_template("index.html", badge="<i>Fixed</i>")\n',{'templates/index.html':template})).length,0);
});
test('Python template proofs retain user data, missing definitions and alternate callers',async t=>{
 const variants=[
  html.replace('badge = "<b>Gold</b>"','badge = request.args.get("html")'),
  html.replace('badge = "<b>Gold</b>"','badge = f"<b>{request.args.get(\'html\')}</b>"'),
  html.replace('    return render_template','    badge += request.args.get("html", "")\n    return render_template'),
  html.replace('    badge = ""\n','').replace('    else:\n        badge = "<b>Standard</b>"\n',''),
  html.replace('    badge = ""','    badge = request.args.get("html")'),
  html.replace('def index():','def index(badge):'),
  html.replace('    badge = ""','    global badge\n    badge = ""'),
  html.replace('    return render_template','    del badge\n    return render_template'),
  html.replace('    return render_template','    for badge in request.args.values():\n        pass\n    return render_template'),
  html.replace('    return render_template','    with manager() as badge:\n        pass\n    return render_template'),
  html.replace('    return render_template','    (badge, other) = values\n    return render_template'),
  html.replace('badge=badge','badge=request.args.get("html")'),
  html.replace('badge=badge','**request.args'),
  html.replace('"index.html",','request.args.get("template"),'),
  html+'\ndef other():\n    return render_template("index.html", badge=request.args.get("html"))\n',
  html+'\n@app.context_processor\ndef inject():\n    return request.args\n',
  html+'\nrender_template = custom\n',
  html+'\nother_render = render_template\n',
  html+'\nfrom overrides import *\n',
  html.replace('    return render_template','    f"{(ｂａｄｇｅ := request.args.get(\'html\'))}"\n    return render_template'),
  html+'\nfrom flask import stream_template\ndef other():\n    return stream_template("index.html", badge=request.args.get("html"))\n',
  html+'\nfrom flask import stream_template_string\ndef other():\n    return stream_template_string("{{ badge | safe }}", badge=request.args.get("html"))\n',
  html.replace('def index():','@replace_renderer\ndef index():'),
 ];
 for(const source of variants)assert.ok(htmlHits(await findings(t,imports+source,{'templates/index.html':template})).length,source);
});
test('Python template proofs check template rebinding, every raw output on a line and module identity',async t=>{
 for(const target of [
  '{{ badge | safe }} {{ user | safe }}',
  '{% set badge = request.args.html %}{{ badge | safe }}',
  '{% for badge in values %}{{ badge | safe }}{% endfor %}',
  '{% macro m(badge) %}{{ badge | safe }}{% endmacro %}',
  '{% include "other.html" %}{{ badge | safe }}',
  '{% autoescape false %}{{ badge | safe }}{% endautoescape %}',
  '{{ badge | safe }} <%- user %>',
 ])assert.ok(htmlHits(await findings(t,imports+html,{'templates/index.html':target})).length,target);
 for(const extra of [
  {'flask.py':'render_template = custom\n'},
  {'another.py':'from flask import render_template\ndef unsafe():\n    return render_template("index.html", badge=request.args.html)\n'},
  {'another.py':'def mutate():\n    globals()["render_template"] = custom\n'},
 ])assert.ok(htmlHits(await findings(t,imports+html,{'templates/index.html':template,...extra})).length);
 assert.ok(htmlHits(await findings(t,imports.replace('Flask(__name__)','Flask(__name__, template_folder="other")')+html,{'templates/index.html':template})).length);
});
test('Python literal template proofs respect branch and loop shadowing',async t=>{
 for(const prefix of ['def nested():\n        nonlocal badge\n        badge = request.args.html\n    nested()','try:\n        pass\n    except Exception as badge:\n        pass','match request.args:\n        case {"html": badge}:\n            pass']){
  const source=imports+html.replace('    return render_template','    '+prefix+'\n    return render_template');
  assert.ok(htmlHits(await findings(t,source,{'templates/index.html':template})).length,prefix);
 }
});
test('Python template proof rejects unsupported render paths even with direct literal bindings',async t=>{
 const safe='def index():\n    return render_template("index.html", badge="<b>Fixed</b>")\n';
 for(const api of ['stream_template','stream_template_string']){
  const source=imports+`from flask import ${api}\n`+safe+`\ndef other():\n    return ${api}("index.html", badge=request.args.get("html"))\n`;
  assert.equal(htmlHits(await findings(t,source,{'templates/index.html':template})).length,1,api);
 }
 for(const change of ['Flask = custom\n','app.route = custom\n','render_template = custom\n','from unknown import *\n'])
  assert.equal(htmlHits(await findings(t,imports+change+safe,{'templates/index.html':template})).length,1,change);
});
test('Python value proofs keep findings for malformed, oversized and unsupported syntax',async t=>{
 for(const source of [sql.replace('    choices','\tchoices'),sql+'\nx = (\n',sql+'\n'+'padding = 0\n'.repeat(18000),sql.replace('    choices','    class Nested:\n        pass\n    choices')])
  assert.ok(sqlHits(await findings(t,imports+source)).length);
 for(const target of [template+'{% if (callback()) %}{% endif %}',template+'{% broken',template+'{% if x %}'.repeat(257),template+'\n'+'x\n'.repeat(100001)])
  assert.ok(htmlHits(await findings(t,imports+html,{'templates/index.html':target})).length,`template bytes=${target.length}, prefix=${target.slice(0,80)}`);
});
