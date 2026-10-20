app.get('/users', (req, res) => {
  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows));
});
