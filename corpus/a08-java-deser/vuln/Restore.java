import java.io.*;
import javax.servlet.http.*;

public class Restore extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try (ObjectInputStream in = new ObjectInputStream(req.getInputStream())) {
            Object state = in.readObject();
        } catch (ClassNotFoundException e) { resp.sendError(400); }
    }
}
