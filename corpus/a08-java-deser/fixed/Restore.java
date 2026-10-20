import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import javax.servlet.http.*;

public class Restore extends HttpServlet {
    private static final ObjectMapper M = new ObjectMapper();
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        State state = M.readValue(req.getInputStream(), State.class);
    }
    static class State { public String step; }
}
