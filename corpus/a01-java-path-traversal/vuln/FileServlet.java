import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;

public class FileServlet extends HttpServlet {
    private static final Path BASE = Paths.get("/srv/files");
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        byte[] data = Files.readAllBytes(BASE.resolve(name));
        response.getOutputStream().write(data);
    }
}
