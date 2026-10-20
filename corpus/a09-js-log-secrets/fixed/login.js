app.post('/login', (req, res) => {
  logger.info({ event: 'login_attempt', user: String(req.body.email) });
  res.sendStatus(204);
});
