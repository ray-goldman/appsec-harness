export async function search(req: Request) {
  const term = new URL(req.url).searchParams.get('q');
  const sql = `SELECT id, title FROM posts WHERE title LIKE '%${term}%'`;
  return prisma.$queryRawUnsafe(sql);
}
export async function byId(req: any) {
  return prisma.$queryRawUnsafe(`SELECT * FROM posts WHERE id = ${req.query.id}`);
}
