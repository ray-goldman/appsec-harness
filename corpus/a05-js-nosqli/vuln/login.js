app.post('/login', async (req, res) => {
  const user = await Users.findOne(req.body);
  if (user) req.session.uid = user._id;
  res.json({ ok: !!user });
});
