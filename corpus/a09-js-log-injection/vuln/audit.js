app.get('/item', (req, res) => {
  logger.info(`item viewed: ${req.query.id}`);
  res.end();
});
