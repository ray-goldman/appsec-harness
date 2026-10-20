app.get('/item', (req, res) => {
  logger.info({ event: 'item_viewed', id: JSON.stringify(req.query.id) });
  res.end();
});
