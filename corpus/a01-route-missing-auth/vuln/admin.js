const express = require('express');
const router = express.Router();
router.delete('/admin/users/:id', async (req, res) => {
  await removeUser(req.params.id);
  res.sendStatus(204);
});
module.exports = router;
