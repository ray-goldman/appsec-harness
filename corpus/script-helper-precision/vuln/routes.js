const { toId } = require("./numbers");
function handler(req) {
  const id = req.query.id;
  db.query("SELECT * FROM records WHERE id = " + id);
}
