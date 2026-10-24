'use strict';
const { safeSource }=require('./cargo');
const { scanSecrets }=require('../rules/secrets');
const FIELDS=new Set(['eco','name','version','spec','line','file','direct','dev','alias','source','checksum','origin','publicRegistry','workspace','resolution','targetFramework']);
const FLAGS=new Set(['direct','dev','publicRegistry','workspace']);
// Reporting is a separate boundary from matching: retain raw identities internally, sanitize new output.
function inventoryForReport(inventory,secretFiles=new Set()) {
  return inventory.map(dep=>Object.fromEntries(Object.entries(dep).filter(([key])=>FIELDS.has(key)).map(([key,value])=>{
    if(value==null)return [key,null];
    if(key==='line')return [key,Number.isSafeInteger(value)&&value>0?value:1];
    if(FLAGS.has(key))return [key,typeof value==='boolean'?value:null];
    if(secretFiles.has(dep.file)&&['name','alias','version','spec','source'].includes(key))return [key,'[REDACTED: source metadata contains detected secret]'];
    if(typeof value!=='string')return [key,'[REDACTED: unsupported metadata shape]'];
    if(value.length>2048)return [key,'[REDACTED: metadata exceeds display budget]'];
    const safe=safeSource(value);
    return [key,scanSecrets('dependency-inventory.txt',safe,[safe]).length?'[REDACTED: metadata contains detected secret]':safe];
  })));
}
module.exports={inventoryForReport};
