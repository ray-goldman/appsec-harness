const libxmljs = require('libxmljs');
function parse(xml) { return libxmljs.parseXml(xml, { noent: false, nonet: true }); }
