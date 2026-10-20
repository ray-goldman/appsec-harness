class StudentDao:
    @staticmethod
    async def create(conn, name: str):
        q = ("INSERT INTO students (name) "
             "VALUES ('%(name)s')" % {'name': name})
        async with conn.cursor() as cur:
            await cur.execute(q)
