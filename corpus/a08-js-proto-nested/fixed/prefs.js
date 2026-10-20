const prefs = new Map();
app.post('/prefs', (req, res) => {
  const { section, key } = req.body;
  prefs.set(`${section}.${key}`, String(req.body.value));
  res.sendStatus(204);
});
