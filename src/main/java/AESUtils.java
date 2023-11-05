import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


import com.alibaba.fastjson.JSON;
import org.apache.commons.codec.binary.Base64;



public final class AESUtils{

    private static final String ALGORITHM = "AES";
    //获取密钥
    public static String genAesSecret(){
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            //下面调用方法的参数决定了生成密钥的长度，可以修改为128, 192或256
            kg.init(256);
            SecretKey sk = kg.generateKey();
            byte[] b = sk.getEncoded();
            String secret = Base64.encodeBase64String(b);
            return secret;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("没有此算法");
        }
    }
    //加密
    public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes) {
        try {
            SecretKey secretKey = getSecretKey(keyBytes);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plainBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //解密
    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes) {
        try {
            SecretKey secretKey = getSecretKey(keyBytes);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(cipherBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private static SecretKey getSecretKey(byte[] keySeed) {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(keySeed);
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(secureRandom);
            return generator.generateKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

