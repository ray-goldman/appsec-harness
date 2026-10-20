const express = require('express');
const router = express.Router();
function safeRedirectPath(p) { return typeof p === 'string' && /^\/[^/\\]/.test(p) ? p : '/'; }
router.get('/after-login', (req, res) => {
  res.redirect(safeRedirectPath(req.query.next));
});
module.exports = router;
