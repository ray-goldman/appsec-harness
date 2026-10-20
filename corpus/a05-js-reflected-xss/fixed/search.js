const escapeHtml = require('escape-html');
app.get('/search', (req, res) => {
  res.send(`<h1>Results for ${escapeHtml(req.query.q)}</h1>`);
});
