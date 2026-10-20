import javax.servlet.http.*;
import java.net.URL;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
public class Web {
    byte[] fetch(HttpServletRequest request) throws Exception { return new URL(request.getParameter("u")).openStream().readAllBytes(); }
    void go(HttpServletRequest request, HttpServletResponse response) throws Exception { response.sendRedirect(request.getParameter("next")); }
    void sec(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception { http.csrf().disable(); }
}
