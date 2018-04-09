import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;

public class RSATest {
    private static String sign(String text, String key) {
        String str = "";
        try {
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            byte[]        md5bytes;
            mdInst.update(text.getBytes());
            md5bytes = mdInst.digest();

            RSAPrivateKey privkey = getPrivateKey(key);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privkey);
            byte[] output = cipher.doFinal(md5bytes);

            for (int i=0; i<output.length; i+=16) {
                str += String.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\r\n",
                    output[i+0],output[i+1],output[i+2 ],output[i+3 ],output[i+4 ],output[i+5 ],output[i+6 ],output[i+7 ],
                    output[i+8],output[i+9],output[i+10],output[i+11],output[i+12],output[i+13],output[i+14],output[i+15]);
            }
        } catch (Exception e) { e.printStackTrace(); }
        return str;
    }

    private static RSAPublicKey getPublicKey(String publicKey) throws Exception {
        Base64 base64 = new Base64();
        byte[] keyBytes = base64.decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    private static RSAPrivateKey getPrivateKey(String privateKey) throws Exception {
        Base64 base64 = new Base64();
        byte[] keyBytes = base64.decode(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    public static void main(String args[]) {
        String PRIVKEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDKdlQyWEj5//v4\n"
                       + "lSQWsLcvv/N5PLhKcLNxwlq/08cByJoy6+p34jclNm6GvG0yVxG/MZ4YshTp8xPG\n"
                       + "dyUV5v4mFjkUBTa0WZb/dy58l7BAicxPi2QGl2oHhM1jexNK4zS0ogzfeOsFwyeY\n"
                       + "KXRYg/bzG5GjTGsyticmq2rJyHgTRMEi/uyizADyWYcksfJbBnO0666B2jyrhJJN\n"
                       + "dFnujJC/rzoXNswcn0gAWTlkhyIZt8IGBQKuKvpdLOgnodsvk3z7sUCwP+ZBS7r6\n"
                       + "nqftoo5sPmHufWlz1vOpWOzC7vHjQe/4AUff5DcXwc7m1PqkeAzyy0n+Y/z2ehd9\n"
                       + "gykCAOmlAgMBAAECggEBALwn3/OxzJBZ7+eDYzibHoOH1lPztCmqN3ofb4sa27Wy\n"
                       + "omt0iEDFwQ4aWflpn+nKtTmEeTLmPT12pAgrrhF+zO7EdGNAvSg6onPkZRVxO2Gf\n"
                       + "Lns2Rc1CZk16hA5R0QolwVOlzmTY0UJXrbJhxDiG27fvBRhH6tAELLppUCMa5Uyx\n"
                       + "TXEyl2eBXSvPKBHyyZWYhHmmtkmAsttRZ+DMTPFxyfYb+cNdINV6ABPJackq4Aa4\n"
                       + "l3P+9b6bVsLtMW6xlaDEPuPm4QmE9eXH8TRm4SjAwssnCbO5Ysj0T+kJVDzXdAA0\n"
                       + "thl16knVNYsavOgB5EEDpRd/+WbZaqy/NKiSHxWW14ECgYEA/PybyVShuX959+CX\n"
                       + "uSWa693a161ZBEm5anI/DN+BP9ktURq7CAEVQeyJyisj1wf8eZC0bvZOSSzlHWRZ\n"
                       + "rwTzer42pVGqYkaGM+ZaMK5a1TLdveCbEIGKnhqtmut6SGIGNA04TNodBkhxJ839\n"
                       + "zDmn0YjQmGmfe7t241TsVcpT7PECgYEAzN+qAnyBorH6jZaodi/jYV0CINSpDFln\n"
                       + "I8dAK+v8iBsMNnIRgiPZfcTAEcJoy16QPdaoukNrp2tTwLne8sQigLBE7ZljBVE5\n"
                       + "QR6j/VKF0tBF5YDUI3SEXhv+CqwfPb6hcz48PeE0N0GXJhKQ5xoaoNUUqEFFlkeJ\n"
                       + "3knEFAG9l/UCgYEA+34raEOn2f3txAsTCU1m6t9LdGixO2AG4Njd8PAnTs+ZCy1l\n"
                       + "jJl3BmgcukuUf2lDBZ5ioIReYsQsp8FgnmpvmS+Kp2G93aB6PRHbytUpGxRL9zxX\n"
                       + "Klt875tZxc4da+N2gzw5Ib0aaWqOgqF2khUmzVgS9dDaaGh90ZRUtRxDviECgYAZ\n"
                       + "5xV5pwBE77e7+xZlivx2rOm9+OU+uHb/4QtOAlI1ayYKJDXufFXdPukB1dCmFdiq\n"
                       + "2N8QXcHYswstzNJRY1bxalfsqn4IiBJzF0qolqxw0QBlWfp4WRz7QRLHiqeQiO+k\n"
                       + "wHOhZz3Q1qwjlilX7sb7GrW36DjCHV1jC3SNCwNLmQKBgDXjNtDJNjslHBKPmLAU\n"
                       + "D7B/U4A60W5mDuxdugFQndxEvHm4Wnn1LuSqTJQu48hdlN8rXD/PYP29eCqP8Heq\n"
                       + "TG4Pk99yKjpir9Dw8KVx16C00dxxs/UwQnUJiiGkoDiCUE04adb05AnzdYtArYVB\n"
                       + "WII5D8QcrCf0w1Chgs9S9/ek\n";
        String signature = sign("\r\nrockcarry\r\nhello\r\n", PRIVKEY);
        System.out.println(signature);
    }
}
