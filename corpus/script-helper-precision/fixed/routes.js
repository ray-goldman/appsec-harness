const { toId } = require("./numbers");
function handler(req) {
  const id = toId(req.query.id);
  db.query("SELECT * FROM records WHERE id = " + id);
}
