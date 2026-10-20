const express = require('express');
const path = require('path');
const app = express();
const FILES = path.join(__dirname, 'files');
app.get('/download', (req, res) => {
  res.sendFile(path.basename(String(req.query.name)), { root: FILES });
});
