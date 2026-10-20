const { exec } = require('node:child_process');
const cfg = require('./config.js');
function handler(req) {
  exec(cfg.REPORT_CMD + ' ' + req.query.path);
}
