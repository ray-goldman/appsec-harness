const jwt = require('jsonwebtoken');
const KEY = process.env.JWT_PRIVATE_KEY, PUB = process.env.JWT_PUBLIC_KEY;
function issue(user) { return jwt.sign({ sub: user.id }, KEY, { algorithm: 'RS256', expiresIn: '15m' }); }
function authenticate(req, res, next) {
  try {
    req.user = jwt.verify(String(req.headers.authorization).split(' ')[1], PUB, { algorithms: ['RS256'] });
    next();
  } catch (e) { res.sendStatus(401); }
}
