app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});
