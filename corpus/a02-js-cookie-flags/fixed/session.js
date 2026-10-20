const session = require('express-session');
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }));
