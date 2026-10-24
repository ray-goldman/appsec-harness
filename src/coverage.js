'use strict';
const path = require('node:path');
const { detectLanguage } = require('./languages');
const { isTestPath } = require('./util');
const { CARGO_SNAPSHOT } = require('./supply');
const SUPPORTED = new Set(['javascript','typescript','python','php','java','kotlin','go','ruby','csharp','shell']);
const UNSUPPORTED = {'.rs':'rust','.c':'c','.h':'c','.cc':'cpp','.cpp':'cpp','.cxx':'cpp','.hpp':'cpp','.hh':'cpp','.swift':'swift','.dart':'dart','.lua':'lua','.pl':'perl','.ex':'elixir','.exs':'elixir','.m':'objective-c','.mm':'objective-cpp'};
function sourceLanguage(file) {
  const logical=file.replace(/\.appsec-quarantined$/,'');
  return UNSUPPORTED[path.extname(logical).toLowerCase()] || (SUPPORTED.has(detectLanguage(logical)) ? detectLanguage(logical) : null);
}
function buildCoverage({files,fileData,skipped,truncated,limits,supply,opts,readFailures=0,osvStatus='not-requested'}) {
  const languages = Object.create(null); let excludedTests=0, excludedVendored=0;
  for(const f of files) {
    const lang=sourceLanguage(f.rel);if(!lang)continue;
    if(fileData.get(f.rel)?.vendored){excludedVendored++;continue;}
    if(!opts.includeTests&&isTestPath(f.rel.replace(/\.appsec-quarantined$/,''))){excludedTests++;continue;}
    const row=languages[lang] ||= {files:0,analyzedFiles:0,unsupportedFiles:0};row.files++;
    if(SUPPORTED.has(lang)&&fileData.get(f.rel)?.sourceAnalyzed)row.analyzedFiles++;
    else if(!SUPPORTED.has(lang))row.unsupportedFiles++;
  }
  const sourceFiles=Object.values(languages).reduce((n,r)=>n+r.files,0),analyzedFiles=Object.values(languages).reduce((n,r)=>n+r.analyzedFiles,0),unsupportedFiles=Object.values(languages).reduce((n,r)=>n+r.unsupportedFiles,0);
  const interrupted=!!(truncated||limits.depth||limits.unreadable||limits.large||readFailures||skipped.symlinks.length||opts.repoSymlinks?.length);
  const cargo=supply.cargo,diagnostics=cargo.inputs.flatMap(i=>i.diagnostics.map(d=>({file:i.file,...d})));
  return {
    schema:'kayfabe/coverage@1',
    source:{status:interrupted||unsupportedFiles||analyzedFiles<sourceFiles?'incomplete':sourceFiles?'complete':'not-applicable',files:sourceFiles,analyzedFiles,unsupportedFiles,languages,note:'Complete means available source checks ran on selected known source files, not exhaustive detection or full parsing. Rust source analysis is unsupported. Other extensions may also be unsupported.'},
    inventory:{status:'limited',note:'Legacy ecosystem inventory parsers have no completeness guarantee. Cargo completeness describes metadata parsing, not dependency resolution, installation or reachability.',cargo:{status:diagnostics.length||interrupted?'incomplete':cargo.inputs.length?'complete':'not-applicable',inputs:cargo.inputs,resolvedPackages:cargo.inventory.filter(d=>d.resolution==='locked').length,requirements:cargo.inventory.filter(d=>d.resolution==='requirement').length,publicRegistryPackages:cargo.inventory.filter(d=>d.publicRegistry).length,diagnostics}},
    advisories:{status:'limited',note:'Curated advisory coverage is limited; absence of matches is not a clean bill of health.',cargoSnapshot:{date:CARGO_SNAPSHOT.date,commit:CARGO_SNAPSHOT.commit,advisories:CARGO_SNAPSHOT.advisories.length,scope:CARGO_SNAPSHOT.scope},online:{status:osvStatus}},
    scope:{includeTests:!!opts.includeTests,excludedTests,excludedVendored,excludedEntries:skipped.excluded||0,skippedDirectories:skipped.dirs,symlinks:skipped.symlinks.length+(opts.repoSymlinks?.length||0),limits:{...limits,readFailures,truncated},note:'Default build/vendor directories, explicit excludes and excluded tests are outside the selected scope. Directory contents are not inventoried.'},
  };
}
function coverageGate(result,required=false) {
  const c=result.coverage,known=c?.schema==='kayfabe/coverage@1';
  const complete=known&&c.source.status==='complete'&&c.source.files>0&&c.inventory.cargo.status!=='incomplete';
  return {required:!!required,passed:!required||!!complete,status:known?(complete?'complete':'incomplete'):'unknown',reason:!known?'Coverage unknown: rescan with a coverage-aware version.':complete?'Available source checks completed in the selected scope; advisory breadth remains limited.':'Incomplete coverage: unsupported/omitted source, no selected source, or incomplete Cargo inventory. Severity findings are evaluated separately.'};
}
function coverageText(result) {
  const c=result.coverage;if(!c)return 'Coverage unknown: this report predates coverage reporting; rescan to measure it.';
  const cargo=c.inventory.cargo;
  return `${coverageGate(result,true).passed?'Source coverage: available checks completed':'Incomplete coverage'} — source ${c.source.analyzedFiles}/${c.source.files} selected files; unsupported ${c.source.unsupportedFiles}. Cargo inventory: ${cargo.status}, ${cargo.resolvedPackages} locked packages, ${cargo.requirements} requirements. Advisory coverage: limited; Cargo snapshot ${c.advisories.cargoSnapshot.date} (${c.advisories.cargoSnapshot.advisories} advisory); OSV ${c.advisories.online.status}.`;
}
module.exports={buildCoverage,coverageGate,coverageText,sourceLanguage};
