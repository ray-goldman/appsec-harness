const { exec } = require('node:child_process');
const { allowed } = require('./hostname.js');
function handler(req) {
  const host = req.query.host;
  if (!allowed(host)) return;
  exec('ping -c1 ' + host);
}
