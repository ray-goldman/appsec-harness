import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.HttpServletRequest;

public class Audit {
    private static final Logger log = LogManager.getLogger(Audit.class);
    void hit(HttpServletRequest request) { log.info("UA: " + request.getHeader("User-Agent")); }
}
