import javax.servlet.http.*;
import javax.naming.directory.*;
import org.owasp.encoder.Encode;

public class Pack {
    String q() { return "SELECT * FROM users WHERE name = ?"; }
    Object ldap(DirContext ctx, String uid, SearchControls c) throws Exception { return ctx.search("ou=people", "(uid={0})", new Object[]{uid}, c); }
    void echo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.resetBuffer();
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().println(Encode.forHtml(request.getParameter("q")));
    }
}
