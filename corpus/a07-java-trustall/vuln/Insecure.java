import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class Insecure implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
