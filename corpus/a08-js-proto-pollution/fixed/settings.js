const ALLOWED = new Set(['theme', 'locale']);
app.post('/settings', (req, res) => {
  for (const [k, v] of Object.entries(req.body)) if (ALLOWED.has(k)) settings.set(k, String(v));
  res.json(Object.fromEntries(settings));
});
