const router = require('express').Router();
router.get('/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  res.json(invoice);
});
module.exports = router;
