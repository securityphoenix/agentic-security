import javax.crypto.Cipher;
import java.security.MessageDigest;

public class CryptoStuff {
  public static void weakHash(byte[] b) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(b);
  }
  public static Cipher des() throws Exception {
    return Cipher.getInstance("DES/CBC/PKCS5Padding");
  }
  public static Cipher aesEcb() throws Exception {
    return Cipher.getInstance("AES/ECB/PKCS5Padding");
  }
}
