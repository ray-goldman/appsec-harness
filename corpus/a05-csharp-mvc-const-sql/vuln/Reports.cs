using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Example.Data;
namespace Example.Web;
public class Reports : ControllerBase {
 [HttpGet("/reports")]
 public string Get(string name) {
  using var command=new SqliteCommand();
  command.CommandText=$"SELECT {QueryText.Columns} FROM records WHERE name='{name}'";
  return "query prepared";
 }
}
