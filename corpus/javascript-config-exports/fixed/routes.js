const { exec } = require('node:child_process');
const cfg = require('./config.js');
function handler(req) {
  exec(cfg.REPORT_CMD + ' ' + cfg.BACKUP_DIR);
}
