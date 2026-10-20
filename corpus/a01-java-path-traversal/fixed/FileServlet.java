import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import org.apache.commons.io.FilenameUtils;

public class FileServlet extends HttpServlet {
    private static final Path BASE = Paths.get("/srv/files");
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = FilenameUtils.getName(request.getParameter("name"));
        Path p = BASE.resolve(name).normalize();
        if (!p.startsWith(BASE)) { response.sendError(400); return; }
        response.getOutputStream().write(Files.readAllBytes(p));
    }
}
