using Microsoft.AspNetCore.Mvc;
using System.IO;
public class FilesController : ControllerBase {
  public IActionResult Read([FromQuery] string input) {
    return LocalRedirect(Url.IsLocalUrl(input) ? input : "/");
  }
}
