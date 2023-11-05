import java.nio.charset.StandardCharsets;
import java.security.Timestamp;
import java.sql.Time;
import java.util.Arrays;
import java.util.Date;

import com.alibaba.fastjson.*;

public class Message {
    private String content;
    private String type;
    private String senderName;
    private String receiverName;

    private String sign;


    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSenderName() {
        return senderName;
    }

    public void setSenderName(String senderName) {
        this.senderName = senderName;
    }

    public String getReceiverName() {
        return receiverName;
    }

    public void setReceiverName(String receiverName) {
        this.receiverName = receiverName;
    }

    public String getSign() {
        return sign;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }

    public Message(){}

    public Message(String content, String type, String senderName, String receiverName, String sign) {
        this.content = content;
        this.type = type;
        this.senderName = senderName;
        this.receiverName = receiverName;
        this.sign = sign;
    }





    public static void main(String[] args) {
        Message getUserInfo = new Message();
        getUserInfo.setType(States.USER_INFO);
        String res = JSON.toJSONString(getUserInfo);
        String res2 = "wasfsfafas";
        System.out.println(res);
        Message newMessage = JSON.parseObject(res2,Message.class);
        System.out.println(newMessage.type);
    }
}
