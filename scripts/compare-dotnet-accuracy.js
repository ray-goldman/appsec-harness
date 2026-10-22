'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function units(report) {
  if (report.apps) return report.apps.flatMap(app => app.cases.map(item => ({...item,id:app.app+'/'+item.id})));
  if (report.cases?.[0]?.parent) return report.cases.flatMap(item => ['parent','fix'].map(variant => ({
    id:item.id+':'+variant,cwe:item.cwe,vulnerable:variant==='parent',outcome:item[variant].outcome,
    revision:item[variant].revision,files:item[variant].files,
  })));
  return report.cases;
}
function metrics(items) {
  const totals={cases:items.length,tp:0,fp:0,tn:0,fn:0};
  for(const item of items) {
    if(!Object.hasOwn(totals,item.outcome)||item.outcome==='cases')throw new Error('invalid unit outcome');
    totals[item.outcome]++;
    if(item.vulnerable!==['tp','fn'].includes(item.outcome))throw new Error('unit outcome contradicts polarity');
  }
  return {...totals,recall:totals.tp+totals.fn?totals.tp/(totals.tp+totals.fn):null,
    falsePositiveRate:totals.fp+totals.tn?totals.fp/(totals.fp+totals.tn):null,
    precision:totals.tp+totals.fp?totals.tp/(totals.tp+totals.fp):null};
}
function compare(before,after) {
  for(const report of [before,after])if(!/^[a-f0-9]{64}$/.test(report.tool?.sourceSha256||report.sourceSha256||''))throw new Error('missing engine source hash');
  const input=report=>report.dataset?.inputSha256||report.inputSha256;
  if(!/^[a-f0-9]{64}$/.test(input(before)||'')||input(before)!==input(after))throw new Error('input hash changed or missing');
  for(const key of ['expectedSha256','labelsSha256','manifestSha256','sourceArchiveSha256','unitManifestSha256']) {
    if(before.dataset?.[key]!==after.dataset?.[key])throw new Error(key+' changed');
  }
  if(JSON.stringify(before.policy)!==JSON.stringify(after.policy))throw new Error('scoring policy changed');
  if(before.evaluatorSha256!==after.evaluatorSha256)throw new Error('evaluator changed');
  if(before.sha256!==after.sha256)throw new Error('annotation hash changed');
  if(JSON.stringify(before.scan?.options)!==JSON.stringify(after.scan?.options))throw new Error('scan options changed');
  const a=units(before),b=units(after);
  if(!Array.isArray(a)||!Array.isArray(b)||a.length!==b.length)throw new Error('unit count changed');
  const label=item=>JSON.stringify([item.id,item.cwe,item.vulnerable,item.file,item.line,item.regions,item.revision,item.files]);
  const byId=new Map(b.map(item=>[item.id,item]));
  if(byId.size!==b.length||new Set(a.map(item=>item.id)).size!==a.length)throw new Error('duplicate unit id');
  const transitions={fpToTn:[],tpToFn:[],tnToFp:[],fnToTp:[]};
  for(const item of a) {
    const next=byId.get(item.id);
    if(!next||label(item)!==label(next))throw new Error('unit label changed: '+item.id);
    const key=item.outcome+'To'+next.outcome[0].toUpperCase()+next.outcome.slice(1);
    if(transitions[key])transitions[key].push(item.id);
  }
  for(const [report,items] of [[before,a],[after,b]]) for(const key of ['cases','tp','fp','tn','fn']) {
    if(metrics(items)[key]!==report.totals[key])throw new Error('reported totals disagree with units');
  }
  const source=report=>report.tool?.sourceSha256||report.sourceSha256;
  const digest=report=>crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex');
  return {inputSha256:input(before),policy:after.policy,
    before:{sourceSha256:source(before),evaluatorSha256:before.evaluatorSha256,canonicalReportSha256:digest(before),totals:metrics(a),scan:before.scan||null,durationMs:before.scan?.durationMs??null},
    after:{sourceSha256:source(after),evaluatorSha256:after.evaluatorSha256,canonicalReportSha256:digest(after),totals:metrics(b),scan:after.scan||null,durationMs:after.scan?.durationMs??null},
    transitions:Object.fromEntries(Object.entries(transitions).map(([key,ids])=>[key,{count:ids.length,ids}]))};
}
function main() {
  const [beforeDir,afterDir,outFile]=process.argv.slice(2);
  if(!beforeDir||!afterDir||!outFile)throw new Error('Usage: node scripts/compare-dotnet-accuracy.js <before> <after> <output.json>');
  const result={schema:'kayfabe-dotnet-accuracy-comparison@1',datasets:{}};
  for(const name of ['csharp','owasp-java','juliet-java','sard','cve-fixes','supplied','dotnet-apps']) {
    const rel=['supplied','dotnet-apps'].includes(name)?name+'.json':name+'/benchmark.json';
    const read=dir=>JSON.parse(fs.readFileSync(path.join(dir,rel),'utf8'));
    const before=read(beforeDir),after=read(afterDir),entry=compare(before,after);
    if(name==='cve-fixes') {
      entry.originalPairs={before:before.pairs,after:after.pairs};
      entry.localized=compare({...before,...before.localized},{...after,...after.localized});
      entry.localizedPairs={before:before.localized.pairs,after:after.localized.pairs};
    }
    if(name==='csharp') {
      entry.byCwe={before:before.byCwe,after:after.byCwe};
      entry.crossFile={before:metrics(units(before).filter(c=>c.id.includes('#'))),after:metrics(units(after).filter(c=>c.id.includes('#')))};
      entry.focusedInjection={cwes:[78,89],interpretation:'Affected diagnostic categories, not all supported CWEs; full-suite totals retain every CWE',before:metrics(units(before).filter(c=>[78,89].includes(c.cwe))),after:metrics(units(after).filter(c=>[78,89].includes(c.cwe)))};
      entry.confidenceStrata={status:'not-measured',reason:'Frozen benchmark matches omit per-finding confidence; do not infer medium+ or high counts.'};
    }
    result.datasets[name]=entry;
  }
  for(const phase of ['before','after']) if(new Set(Object.values(result.datasets).map(dataset=>dataset[phase].sourceSha256)).size!==1)throw new Error('mixed engine versions in '+phase);
  fs.mkdirSync(path.dirname(path.resolve(outFile)),{recursive:true});
  fs.writeFileSync(outFile,JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify(Object.fromEntries(Object.entries(result.datasets).map(([name,r])=>[name,{before:r.before.totals,after:r.after.totals,transitions:Object.fromEntries(Object.entries(r.transitions).map(([key,value])=>[key,value.count]))}]))));
}
if(require.main===module)main();
module.exports={compare,metrics,units};
