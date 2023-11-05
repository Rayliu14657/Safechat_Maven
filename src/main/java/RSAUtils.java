import org.springframework.core.io.ClassPathResource;
import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


public class RSAUtils {
    //密钥对字符串
    private static Map<String, String> keyPairString = new HashMap<String, String>();
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    //加密算法
    private static final String KEYALG = "RSA";
    private static final String SIGALG = "SHA1WithRSA";
    private static String path = "";

    private KeyStore keyStore;

    public static Map<String, String> getKeyPair() {
        return keyPairString;
    }

    public static PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }



    public static void genKeyPair(String name) throws Exception {
        //以 PKCS12 规格，创建 KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(new ClassPathResource("certs/rayliu.keystore").getFile()), "12345sun".toCharArray());
        char[] keyPassword = "12345sun".toCharArray();
        keyPairString.clear();

        privateKey = (PrivateKey) keyStore.getKey(name, keyPassword);
        keyPairString.put("PR", new String(Base64.getEncoder().encode(privateKey.getEncoded())));

        Certificate certificate = keyStore.getCertificate(name);
        publicKey = certificate.getPublicKey();
        keyPairString.put("PU", new String(Base64.getEncoder().encode(publicKey.getEncoded())));
    }

    public static Map<String,PublicKey> getPublicKeyMap() throws Exception {
        ConcurrentHashMap<String,PublicKey>keyMap = new ConcurrentHashMap<>();
        //以 PKCS12 规格，创建 KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(new ClassPathResource("certs/rayliu.keystore").getFile()), "12345sun".toCharArray());
        char[] keyPassword = "12345sun".toCharArray();
        Enumeration<String> aliases = keyStore.aliases();
        String alias = null;
        while (aliases.hasMoreElements()){
            alias = aliases.nextElement();
            Certificate certificate = keyStore.getCertificate(alias);
            PublicKey pu = certificate.getPublicKey();
            keyMap.put(alias,pu);
        }
        return keyMap;
    }

    public static Map<String,String> getPublicKeyStringMap() throws Exception {
        ConcurrentHashMap<String,String>keyMap = new ConcurrentHashMap<>();
        //以 PKCS12 规格，创建 KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(new ClassPathResource("certs/rayliu.keystore").getFile()), "12345sun".toCharArray());
        char[] keyPassword = "12345sun".toCharArray();
        Enumeration<String> aliases = keyStore.aliases();
        String alias = null;
        while (aliases.hasMoreElements()){
            alias = aliases.nextElement();
            Certificate certificate = keyStore.getCertificate(alias);
            PublicKey pu = certificate.getPublicKey();
            keyMap.put(alias,new String(Base64.getEncoder().encode(pu.getEncoded())));
        }
        return keyMap;
    }

    public static byte[] sign(String content, PrivateKey priKey) throws Exception {
        Signature signature = Signature.getInstance(SIGALG);
        signature.initSign(priKey);
        signature.update(content.getBytes());
        return signature.sign();
    }

    public static boolean verify(String content, byte[] sign, PublicKey pubKey) throws Exception {

        Signature signature = Signature.getInstance(SIGALG);
        signature.initVerify(pubKey);
        signature.update(content.getBytes());
        return signature.verify(sign);
    }

    public static String encrypt(String content, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.getMimeDecoder().decode(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(KEYALG).generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance(KEYALG);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.getEncoder().encodeToString(cipher.doFinal(content.getBytes("UTF-8")));
        return outStr;
    }

    public static String decrypt(String content, String privateKey) throws Exception {

        //64位解码加密后的字符串
        byte[] inputByte = Base64.getMimeDecoder().decode(content);
        //        //base64编码的私钥
        byte[] decoded = Base64.getMimeDecoder().decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte));
        return outStr;
    }




}
