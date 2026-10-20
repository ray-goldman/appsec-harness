using System.Data.SqlClient;
public class Repo {
    public SqlDataReader Find(SqlConnection conn, string name) {
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{name}'", conn);
        return cmd.ExecuteReader();
    }
}
