const _ = require('lodash');
app.post('/settings', (req, res) => {
  _.merge(settings, req.body);
  res.json(settings);
});
