const jwt = require('jsonwebtoken');
function issue(user) { return jwt.sign({ sub: user.id }, 'supersecret123'); }
function authenticate(req, res, next) {
  const claims = jwt.decode(req.headers.authorization.split(' ')[1]);
  req.user = claims;
  next();
}
