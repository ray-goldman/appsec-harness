using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
class Lookup : ControllerBase {
  public IActionResult Run([FromQuery] string host) {
    if (host != "example.com") throw new ArgumentException();
    var start = new ProcessStartInfo("nslookup");
    start.ArgumentList.Add(host);
    Process.Start(start);
    return Ok();
  }
}
