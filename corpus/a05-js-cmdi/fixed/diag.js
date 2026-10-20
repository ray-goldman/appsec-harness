const { execFile } = require('child_process');
const HOST = /^[a-z0-9.-]{1,253}$/i;
app.post('/diag/ping', (req, res) => {
  const host = String(req.body.host);
  if (!HOST.test(host)) return res.sendStatus(400);
  execFile('ping', ['-c', '1', '--', host], (err, out) => res.send(out));
});
