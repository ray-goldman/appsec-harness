using System.Diagnostics;
namespace Example;
class Jobs { public void Send(string input) {
var choices = new Dictionary<string,string>(StringComparer.Ordinal) { ["alpha"] = "alpha", ["beta"] = "beta" };
if (!choices.TryGetValue(input, out var selected)) throw new ArgumentException("Unknown job");

var p = new ProcessStartInfo("cmd.exe");
p.Arguments = "/c echo " + selected;
Process.Start(p);
} }
