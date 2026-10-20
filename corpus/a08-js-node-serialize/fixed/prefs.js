app.get('/', (req, res) => {
  let prefs = {};
  try { prefs = JSON.parse(Buffer.from(req.cookies.prefs || '', 'base64').toString()); } catch { prefs = {}; }
  res.json({ theme: String(prefs.theme || 'light') });
});
