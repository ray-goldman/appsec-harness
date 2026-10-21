using System.IO;
class Query {
    void Run(string path, Db db) {
        var value = File.ReadAllText(path);
        db.FromSqlInterpolated($"select * from Items where Name = {value}");
    }
}
