const express = require('express');
const path = require('path');
const app = express();
app.get('/download', (req, res) => {
  const file = path.join(__dirname, 'files', req.query.name);
  res.sendFile(file);
});
