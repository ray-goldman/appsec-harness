class StudentDao:
    @staticmethod
    async def create(conn, name: str):
        q = "INSERT INTO students (name) VALUES (%(name)s)"
        async with conn.cursor() as cur:
            await cur.execute(q, {"name": name})
