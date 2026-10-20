#!/usr/bin/env node
'use strict';
const { main } = require('../src/cli');

main(process.argv.slice(2)).then(
  (code) => { if (typeof code === 'number') process.exitCode = code; },
  (err) => { process.stderr.write(`appsec: ${err && err.message ? err.message : err}\n`); if (process.env.APPSEC_DEBUG) console.error(err); process.exitCode = 2; },
);
