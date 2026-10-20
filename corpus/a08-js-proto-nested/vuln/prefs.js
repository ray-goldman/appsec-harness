app.post('/prefs', (req, res) => {
  const { section, key } = req.body;
  prefs[section][key] = req.body.value;
  res.sendStatus(204);
});
