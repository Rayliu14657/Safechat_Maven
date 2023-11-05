import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class MessageDigestUtils {
    public static String getMessageDigest(String message) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA");
        messageDigest.update(message.getBytes(StandardCharsets.ISO_8859_1));
        byte[] bytes = messageDigest.digest();
        String msgDigest = Base64.getEncoder().encodeToString(bytes);
        return msgDigest;
    }

}
