import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Crypto {
    Cipher c() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
    byte[] h(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }
    String sessionToken = Long.toHexString(new SecureRandom().nextLong());
}
