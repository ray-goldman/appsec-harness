import javax.net.ssl.*;

public class Secure {
    public SSLContext ctx() throws Exception {
        SSLContext c = SSLContext.getInstance("TLSv1.3");
        c.init(null, null, null);
        return c;
    }
}
