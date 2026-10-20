import javax.servlet.http.HttpServletRequest;

public class Lookup {
    void run(HttpServletRequest request) throws Exception {
        String cmd = "nslookup " + request.getParameter("domain");
        Runtime.getRuntime().exec(cmd);
    }
}
