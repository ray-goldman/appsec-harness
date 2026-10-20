const bcrypt = require('bcrypt');
const hash = (pw) => bcrypt.hash(pw, 4);
