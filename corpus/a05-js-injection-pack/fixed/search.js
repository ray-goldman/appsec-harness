const escapeRegExp = require('escape-string-regexp');
app.get('/s', (req, res) => {
  const re = new RegExp(escapeRegExp(String(req.query.q)));
  res.json(items.filter((i) => re.test(i)));
});
app.get('/h', (req, res) => {
  res.setHeader('X-Name', encodeURIComponent(String(req.query.name)));
  res.end();
});
