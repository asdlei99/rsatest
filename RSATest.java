import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;

public class RSATest {
    public static String sign(String text, String key) {
        String str = "";
        try {
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            byte[]        md5bytes;
            mdInst.update(text.getBytes());
            md5bytes = mdInst.digest();

            Base64 base64 = new Base64();
            byte[] buffer = base64.decode(key);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(buffer);
            RSAPublicKey pubkey = (RSAPublicKey)factory.generatePublic(spec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            byte[] output = cipher.doFinal(md5bytes);

            for (int i=0; i<output.length; i+=16) {
                str += String.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\r\n",
                    output[i+0],output[i+1],output[i+2 ],output[i+3 ],output[i+4 ],output[i+5 ],output[i+6 ],output[i+7 ],
                    output[i+8],output[i+9],output[i+10],output[i+11],output[i+12],output[i+13],output[i+14],output[i+15]);
            }
        } catch (Exception e) { e.printStackTrace(); }
        return str;
    }

    public static void main(String args[]) {
        String PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAynZUMlhI+f/7+JUkFrC3\n"
                      + "L7/zeTy4SnCzccJav9PHAciaMuvqd+I3JTZuhrxtMlcRvzGeGLIU6fMTxnclFeb+\n"
                      + "JhY5FAU2tFmW/3cufJewQInMT4tkBpdqB4TNY3sTSuM0tKIM33jrBcMnmCl0WIP2\n"
                      + "8xuRo0xrMrYnJqtqych4E0TBIv7soswA8lmHJLHyWwZztOuugdo8q4SSTXRZ7oyQ\n"
                      + "v686FzbMHJ9IAFk5ZIciGbfCBgUCrir6XSzoJ6HbL5N8+7FAsD/mQUu6+p6n7aKO\n"
                      + "bD5h7n1pc9bzqVjswu7x40Hv+AFH3+Q3F8HO5tT6pHgM8stJ/mP89noXfYMpAgDp\n"
                      + "pQIDAQAB\n";
        String signature = sign("\r\nrockcarry\r\nhello\r\n", PUBKEY);
        System.out.println(signature);
    }
}
