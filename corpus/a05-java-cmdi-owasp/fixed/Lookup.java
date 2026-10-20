import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

public class Lookup {
    private static final Pattern HOST = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");
    static String validateHostname(String h) { if (h == null || !HOST.matcher(h).matches()) throw new IllegalArgumentException(); return h; }
    void run(HttpServletRequest request) throws Exception {
        String domain = validateHostname(request.getParameter("domain"));
        new ProcessBuilder("nslookup", "--", domain).start();
    }
}
