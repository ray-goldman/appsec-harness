using System.Data.SqlClient;
using System.Diagnostics;
public class Repo {
    public void Run(string name, string argument, SqlConnection connection) {
        var command = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", connection);
        command.ExecuteNonQuery();
        string prefix = "cmd /c ";
        Process.Start(prefix + argument);
    }
}
