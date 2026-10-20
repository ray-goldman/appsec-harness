const multer = require('multer');
const crypto = require('crypto');
const storage = multer.diskStorage({
  destination: '/var/app-data/uploads',
  filename: (req, file, cb) => cb(null, crypto.randomUUID()),
});
