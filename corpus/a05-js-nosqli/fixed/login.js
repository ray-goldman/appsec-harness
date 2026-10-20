app.post('/login', async (req, res) => {
  const user = await Users.findOne({ email: String(req.body.email) });
  const ok = !!user && await argon2.verify(user.hash, String(req.body.password));
  if (ok) req.session.regenerate(() => { req.session.uid = user._id; res.json({ ok }); });
  else res.status(401).json({ ok: false });
});
