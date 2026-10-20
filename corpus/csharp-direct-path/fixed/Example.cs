using Microsoft.AspNetCore.Mvc;
using System.IO;
public class FilesController : ControllerBase {
  public IActionResult Read([FromQuery] string input) {
    var full = Path.GetFullPath(Path.Combine("/srv/files", input));
    if (!full.StartsWith("/srv/files/", StringComparison.Ordinal)) return BadRequest();
    return PhysicalFile(full, "application/octet-stream");
  }
}
