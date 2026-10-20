using Microsoft.AspNetCore.Mvc;
using System.IO;
public class FilesController : ControllerBase {
  public IActionResult Read([FromQuery] string input) {
    return PhysicalFile(Path.Combine("/srv/files", input), "application/octet-stream");
  }
}
