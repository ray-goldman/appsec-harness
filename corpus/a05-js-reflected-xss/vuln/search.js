app.get('/search', (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1>`);
});
