import javax.servlet.http.*;
import javax.naming.directory.*;

public class Pack {
    String q(HttpServletRequest request) { return "SELECT * FROM users WHERE name = '" + request.getParameter("n") + "'"; }
    Object ldap(DirContext ctx, String uid, SearchControls c) throws Exception { return ctx.search("ou=people", "(uid=" + uid + ")", c); }
    void echo(HttpServletRequest request, HttpServletResponse response) throws Exception { response.getWriter().println(request.getParameter("q")); }
}
