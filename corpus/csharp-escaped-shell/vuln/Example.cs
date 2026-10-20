using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
class Lookup : ControllerBase {
  public IActionResult Run([FromQuery] string host) {
    Process.Start("/bin/sh", "-c \"nslookup " + host + "\"");
    return Ok();
  }
}
