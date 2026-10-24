using Example.Data;
namespace Example.Web;
public sealed class Reports {
 public void Search(dynamic command, string columns, string name) {
  QueryText.Columns = columns;
  command.CommandText = $"SELECT {QueryText.Columns} FROM records WHERE name = $name";
  command.Parameters.AddWithValue("$name", name);
 }
}
