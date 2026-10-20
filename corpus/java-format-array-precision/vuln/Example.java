import javax.servlet.http.*;
public class Example extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    String input = request.getParameter("value");
    String clean = org.springframework.web.util.HtmlUtils.htmlEscape(input);
    Object[] parts = {input, clean};
    response.getWriter().printf("<p>%1$s: %2$s</p>", parts);
  }
}
