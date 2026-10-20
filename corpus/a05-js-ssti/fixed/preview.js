const ejs = require('ejs');
app.post('/preview', (req, res) => {
  res.render('preview', { body: String(req.body.text), user: req.user });
});
