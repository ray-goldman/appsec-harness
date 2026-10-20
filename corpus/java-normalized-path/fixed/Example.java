import java.nio.file.*;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;
public class Example {
  private static final Path ROOT = Paths.get("/srv/files").toAbsolutePath();
  public byte[] read(@RequestParam String file) throws IOException {
    Path p = ROOT.resolve(file).normalize();
    if (!p.startsWith(ROOT)) throw new SecurityException("bad path");
    return Files.readAllBytes(p);
  }
}
