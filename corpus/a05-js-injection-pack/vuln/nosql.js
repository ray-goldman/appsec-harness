function byName(db, name) {
  return db.users.find({ $where: "this.name == '" + name + "'" });
}
