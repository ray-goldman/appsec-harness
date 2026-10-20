const cors = require('cors');
const ALLOWED = ['https://app.example.com'];
app.use(cors({ origin: ALLOWED, credentials: true }));
