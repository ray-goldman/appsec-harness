import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.util.Random;

public class Crypto {
    Cipher c() throws Exception { return Cipher.getInstance("DES/ECB/PKCS5Padding"); }
    byte[] h(byte[] b) throws Exception { return MessageDigest.getInstance("MD5").digest(b); }
    String sessionToken = Long.toHexString(new Random().nextLong());
}
