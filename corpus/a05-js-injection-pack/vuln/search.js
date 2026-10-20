app.get('/s', (req, res) => {
  const re = new RegExp(req.query.q);
  res.json(items.filter((i) => re.test(i)));
});
app.get('/h', (req, res) => {
  res.setHeader('X-Name', req.query.name);
  res.end();
});
