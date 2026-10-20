const ejs = require('ejs');
app.post('/preview', (req, res) => {
  res.send(ejs.render(req.body.template, { user: req.user }));
});
