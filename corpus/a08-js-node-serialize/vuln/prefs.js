const serialize = require('node-serialize');
app.get('/', (req, res) => {
  const prefs = serialize.unserialize(Buffer.from(req.cookies.prefs, 'base64').toString());
  res.json(prefs);
});
