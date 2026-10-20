const crypto = require('crypto');
const argon2 = require('argon2');
async function hashPassword(pw) { return argon2.hash(pw, { type: argon2.argon2id }); }
function newResetToken() { return crypto.randomBytes(32).toString('base64url'); }
module.exports = { hashPassword, newResetToken };
