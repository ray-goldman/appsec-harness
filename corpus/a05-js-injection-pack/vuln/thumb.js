const { spawn } = require('child_process');
function thumb(file) { return spawn('convert', [file, 'out.png'], { shell: true }); }
