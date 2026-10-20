import javax.servlet.http.*;
import java.net.URL;
import java.util.Map;
import org.springframework.security.config.Customizer;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "https://app.example.com")
public class Web {
    private static final Map<String, String> UPSTREAMS = Map.of("rates", "https://rates.example.net/v1");
    byte[] fetch(HttpServletRequest request) throws Exception { String target = UPSTREAMS.getOrDefault(request.getParameter("svc"), "https://rates.example.net/v1"); return new URL(target).openStream().readAllBytes(); }
    void go(HttpServletRequest request, HttpServletResponse response) throws Exception { response.sendRedirect("/home"); }
    void sec(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception { http.csrf(Customizer.withDefaults()); }
}
