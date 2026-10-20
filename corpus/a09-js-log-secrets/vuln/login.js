app.post('/login', (req, res) => {
  console.log('login attempt', req.body);
  res.sendStatus(204);
});
