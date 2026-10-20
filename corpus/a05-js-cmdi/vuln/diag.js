const { exec } = require('child_process');
app.post('/diag/ping', (req, res) => {
  exec(`ping -c 1 ${req.body.host}`, (err, out) => res.send(out));
});
