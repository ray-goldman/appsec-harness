import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class Audit {
    private static final Logger log = LoggerFactory.getLogger(Audit.class);
    void hit(HttpServletRequest request) { log.info("UA length {}", String.valueOf(request.getHeader("User-Agent")).length()); }
}
