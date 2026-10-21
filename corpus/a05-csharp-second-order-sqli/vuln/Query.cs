using System.IO;
class Query {
    void Run(string path, Db db) {
        var sql = File.ReadAllText(path);
        db.FromSqlRaw(sql);
    }
}
