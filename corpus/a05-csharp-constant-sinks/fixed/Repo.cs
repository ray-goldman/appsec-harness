using System.Data.SqlClient;
using System.Diagnostics;
public class Repo {
    public void Run(string name, string argument, SqlConnection connection) {
        var command = new SqlCommand("SELECT * FROM Users WHERE Name = @name", connection);
        command.Parameters.AddWithValue("@name", name);
        command.ExecuteNonQuery();
        var start = new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", "echo", argument } };
        Process.Start(start);
    }
}
