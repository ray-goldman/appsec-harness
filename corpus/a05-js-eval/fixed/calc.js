const { evaluate } = require('mathjs');
app.get('/calc', (req, res) => {
  res.json({ result: evaluate(String(req.query.expr)) });
});
