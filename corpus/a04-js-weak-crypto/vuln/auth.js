const crypto = require('crypto');
function hashPassword(pw) { return crypto.createHash('md5').update(pw).digest('hex'); }
function newResetToken() { const resetToken = Math.random().toString(36).slice(2); return resetToken; }
module.exports = { hashPassword, newResetToken };
