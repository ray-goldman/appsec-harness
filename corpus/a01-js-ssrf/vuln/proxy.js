const express = require('express');
const app = express();
app.get('/preview', async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target);
  res.type(r.headers.get('content-type')).send(Buffer.from(await r.arrayBuffer()));
});
