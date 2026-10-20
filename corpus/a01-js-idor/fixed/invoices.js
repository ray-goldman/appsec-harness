const router = require('express').Router();
router.get('/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findOne({ _id: req.params.id, owner: req.user.id });
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});
module.exports = router;
