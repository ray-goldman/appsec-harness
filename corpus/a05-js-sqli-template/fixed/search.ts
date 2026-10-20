export async function search(req: Request) {
  const term = new URL(req.url).searchParams.get('q') ?? '';
  return prisma.$queryRaw`SELECT id, title FROM posts WHERE title LIKE ${'%' + term + '%'}`;
}
