const { read } = require("./input");
function handler(req) {
  const id = read(req, "id");
  db.query("SELECT * FROM records WHERE id = " + id);
}
