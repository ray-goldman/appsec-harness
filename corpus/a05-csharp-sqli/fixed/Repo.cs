using System.Data.SqlClient;
public class Repo {
    public SqlDataReader Find(SqlConnection conn, string name) {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        return cmd.ExecuteReader();
    }
}
