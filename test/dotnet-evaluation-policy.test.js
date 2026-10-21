'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const datasetsPath = path.join(root, 'docs/benchmarks/dotnet-datasets.json');
const policyPath = path.join(root, 'docs/benchmarks/dotnet-evaluation-policy.md');
const coveragePath = path.join(root, 'docs/DOTNET-COVERAGE.md');

test('existing .NET datasets are tiered and prior held-out claims are corrected', () => {
  assert.ok(fs.existsSync(datasetsPath), 'dataset registry exists');
  assert.ok(fs.existsSync(policyPath), 'evaluation policy exists');
  assert.ok(fs.existsSync(coveragePath), 'coverage report exists');
  const datasets = JSON.parse(fs.readFileSync(datasetsPath, 'utf8'));
  const policy = fs.readFileSync(policyPath, 'utf8');
  const coverage = fs.readFileSync(coveragePath, 'utf8');
  const byId = new Map(datasets.datasets.map(dataset => [dataset.id, dataset]));
  assert.equal(byId.get('own-dotnet-apps').tier, 'self-authored-regression');
  assert.equal(byId.get('own-dotnet-apps').independent, false);
  assert.equal(byId.get('juliet-csharp-held').tier, 'third-party-real-code');
  assert.equal(byId.get('juliet-csharp-held').status, 'seen-development');
  assert.equal(byId.get('juliet-csharp-held').retiredAsHoldout, true);
  assert.equal(byId.get('eshop').status, 'seen');
  assert.equal(byId.get('webgoat-dotnet').status, 'seen');
  assert.equal(byId.get('eshop').eligibleForPublicRepositorySample, false);
  assert.equal(byId.get('webgoat-dotnet').eligibleForPublicRepositorySample, false);
  assert.match(policy, /prior held-out scores are not blind/i);
  assert.match(coverage, /self-authored regression/i);
  assert.match(coverage, /held half is retired/i);
});

test('evaluation policy separates tiers and marks unavailable gates not measured', () => {
  assert.ok(fs.existsSync(policyPath), 'evaluation policy exists');
  const policy = fs.readFileSync(policyPath, 'utf8');
  assert.match(policy, /Self-authored regression/);
  assert.match(policy, /Independently authored/);
  assert.match(policy, /Third-party real code/);
  assert.match(policy, /not measured/i);
  assert.match(policy, /two adjudicators per finding/i);
  assert.match(policy, /lower bound of a 95% Wilson interval/i);
});
