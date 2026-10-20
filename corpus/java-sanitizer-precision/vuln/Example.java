import javax.servlet.http.*;
public class Example extends HttpServlet {
  private String encode(String value) {
    return org.springframework.web.util.HtmlUtils.htmlEscape(value);
  }
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    String input = request.getParameter("value");
    String clean = encode(input);
    String alias = clean;
    response.getWriter().print("<p>" + alias + input + "</p>");
  }
}
