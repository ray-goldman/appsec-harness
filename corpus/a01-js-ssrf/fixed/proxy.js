const express = require('express');
const app = express();
const UPSTREAMS = { avatars: 'https://avatars.example.net/', docs: 'https://docs.example.net/' };
app.get('/preview', async (req, res) => {
  const base = UPSTREAMS[req.query.service];
  if (!base) return res.sendStatus(400);
  const r = await fetch(base + 'index.json');
  res.json(await r.json());
});
