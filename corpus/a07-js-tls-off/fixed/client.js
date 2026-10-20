const https = require('https');
const fs = require('fs');
const agent = new https.Agent({ ca: fs.readFileSync('/etc/ssl/private-ca.pem') });
module.exports = agent;
