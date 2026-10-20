const crypto = require('crypto');
app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  logger.error({ id, err });
  res.status(500).json({ error: 'internal error', id });
});
