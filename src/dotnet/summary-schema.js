'use strict';

const SUMMARY_SCHEMA_VERSION = 1;
function createMethodSummary({ methodId, parameters = [], parameterToReturn = [], parameterToSinks = [], parameterToFields = [], sourcesToReturn = [], sourcesToFields = [], sanitizersBySink = {}, unresolvedCallSites = [] }) {
  if (typeof methodId !== 'string' || !methodId) throw new TypeError('methodId is required');
  return { schemaVersion: SUMMARY_SCHEMA_VERSION, methodId, parameters, parameterToReturn, parameterToSinks, parameterToFields,
    sourcesToReturn, sourcesToFields, sanitizersBySink, unresolvedCallSites };
}
function serializeMethodSummary(summary) {
  validateMethodSummary(summary);
  return JSON.stringify(summary);
}
function validateMethodSummary(summary) {
  if (!summary || summary.schemaVersion !== SUMMARY_SCHEMA_VERSION) throw new Error(`unsupported summary schema: ${summary?.schemaVersion}`);
  if (typeof summary.methodId !== 'string' || !summary.methodId) throw new Error('invalid method summary methodId');
  return summary;
}
function deserializeMethodSummary(serialized) { return validateMethodSummary(JSON.parse(serialized)); }

module.exports = { SUMMARY_SCHEMA_VERSION, createMethodSummary, serializeMethodSummary, deserializeMethodSummary, validateMethodSummary };
