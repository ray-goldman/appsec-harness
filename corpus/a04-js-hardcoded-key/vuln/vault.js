const crypto = require('crypto');
function enc(text, iv) {
  const c = crypto.createCipheriv('aes-256-cbc', 'k3y-th4t-sh0uld-n0t-b3-h3r3-0123', iv);
  return c.update(text, 'utf8', 'hex') + c.final('hex');
}
function legacy(text) { return crypto.createCipher('aes192', process.env.K).update(text); }
