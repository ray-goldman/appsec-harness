app.put('/me', requireAuth, async (req, res) => {
  const { displayName, bio } = req.body;
  const user = await User.findByIdAndUpdate(req.user.id, { displayName, bio }, { new: true });
  res.json(user);
});
