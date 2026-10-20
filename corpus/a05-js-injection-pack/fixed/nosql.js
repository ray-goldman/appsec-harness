function byName(db, name) {
  return db.users.find({ name: String(name) });
}
