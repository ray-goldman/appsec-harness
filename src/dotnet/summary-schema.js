'use strict';

const SUMMARY_SCHEMA_VERSION = 1;
function createMethodSummary({ methodId, parameters = [], parameterToReturn = [], parameterToSinks = [], parameterToFields = [], sourcesToReturn = [], sourcesToFields = [], sanitizersBySink = {}, unresolvedCallSites = [] }) {
  if (typeof methodId !== 'string' || !methodId) throw new TypeError('methodId is required');
  return validateMethodSummary({ schemaVersion: SUMMARY_SCHEMA_VERSION, methodId, parameters, parameterToReturn, parameterToSinks, parameterToFields,
    sourcesToReturn, sourcesToFields, sanitizersBySink, unresolvedCallSites });
}
function serializeMethodSummary(summary) {
  validateMethodSummary(summary);
  return JSON.stringify(summary);
}
function validateMethodSummary(summary) {
  if (!summary || summary.schemaVersion !== SUMMARY_SCHEMA_VERSION) throw new Error(`unsupported summary schema: ${summary?.schemaVersion}`);
  if (typeof summary.methodId !== 'string' || !summary.methodId) throw new Error('invalid method summary methodId');
  for (const field of ['parameters','parameterToReturn','parameterToSinks','parameterToFields','sourcesToReturn','sourcesToFields','unresolvedCallSites']) {
    if (!Array.isArray(summary[field])) throw new Error('invalid method summary '+field);
  }
  const index=p=>Number.isInteger(p)&&p>=0&&p<summary.parameters.length;
  const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
  if (!summary.parameters.every(p=>object(p)&&typeof p.name==='string'&&p.name) ||
      !summary.parameterToReturn.every(index) ||
      !summary.parameterToSinks.every(s=>object(s)&&index(s.parameter)&&typeof s.category==='string'&&typeof s.sanitized==='boolean') ||
      !summary.parameterToFields.every(s=>object(s)&&index(s.parameter)&&typeof s.field==='string') ||
      !summary.sourcesToReturn.every(s=>typeof s==='string') ||
      !summary.sourcesToFields.every(s=>object(s)&&typeof s.source==='string'&&typeof s.field==='string') ||
      !summary.unresolvedCallSites.every(s=>object(s)&&typeof s.reason==='string') ||
      !object(summary.sanitizersBySink)||!Object.values(summary.sanitizersBySink).every(v=>typeof v==='boolean')) {
    throw new Error('invalid method summary flow data');
  }
  return summary;
}
function deserializeMethodSummary(serialized) { return validateMethodSummary(JSON.parse(serialized)); }

module.exports = { SUMMARY_SCHEMA_VERSION, createMethodSummary, serializeMethodSummary, deserializeMethodSummary, validateMethodSummary };
