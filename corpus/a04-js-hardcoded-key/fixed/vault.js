const crypto = require('crypto');
const KEY = Buffer.from(process.env.DATA_KEY_B64, 'base64');
function enc(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return { iv, ct, tag: c.getAuthTag() };
}
