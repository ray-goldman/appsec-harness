const libxmljs = require('libxmljs');
function parse(xml) { return libxmljs.parseXml(xml, { noent: true }); }
