app.use((err, req, res, next) => { logger.error(err); res.status(500).json({ error: 'internal' }); });
