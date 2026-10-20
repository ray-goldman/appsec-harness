const express = require('express');
const router = express.Router();
router.get('/after-login', (req, res) => {
  res.redirect(req.query.next);
});
module.exports = router;
