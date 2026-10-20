const crypto = require('crypto');
function checkKey(req, apiKeyBuf) {
  const got = Buffer.from(String(req.headers['x-api-key'] || ''));
  return got.length === apiKeyBuf.length && crypto.timingSafeEqual(got, apiKeyBuf);
}
