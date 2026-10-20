function allowed(host) {
  return typeof host === 'string' && host.length > 0 && host.length <= 253 && !/[^a-z0-9.-]/i.test(host);
}
module.exports = { allowed };
