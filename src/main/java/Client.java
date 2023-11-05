import com.alibaba.fastjson.JSON;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;


public class Client extends JFrame {      //客户机窗体类
    // 该图形界面拥有四块区域，分别位于上、左、中、下 （up、Left、middle、down）。
    private JPanel panUp = new JPanel();
    private JPanel panLeft = new JPanel();
    private JPanel panMid = new JPanel();
    private JPanel panDown = new JPanel();

    // panUp 区域的子节点定义，3个标签、3个输入框、2个按钮
    private JLabel lblLocalPort1 = new JLabel("服务器IP: ");
    private JLabel lblLocalPort2 = new JLabel("端口: ");
    private JLabel lblLocalPort3 = new JLabel("本人昵称: ");
    protected JTextField tfLocalPort1 = new JTextField(15);
    protected JTextField tfLocalPort2 = new JTextField(5);
    protected JTextField tfLocalPort3 = new JTextField(5);
    protected JButton butStart = new JButton("连接服务器");
    protected JButton butStop = new JButton("断开服务器");
    // panLeft 区域的子节点定义，显示框、滚动条
    protected JTextArea taMsg = new JTextArea(25, 25);
    JScrollPane scroll = new JScrollPane(taMsg);
    // panMid 区域的子节点定义，lstUsers在线用户界面
    JList lstUsers = new JList();
    // panDown 区域的子节点定义，标签，输入框
    private JLabel lblLocalPort4 = new JLabel("消息（按回车发送）: ");
    protected JTextField tfLocalPort4 = new JTextField(20);
    private JComboBox<String> usersToSend = new JComboBox<String>();
    private JLabel lbSendUser = new JLabel("选择发送用户");
    private JButton connButton = new JButton("连线对方");




    /**
     * ===== 变量分割 =====
     * 上面是图形界面变量，下面是存放数据的变量
     */
    BufferedReader in;
    PrintStream out;
    public static int localPort = 8000;     // 默认端口
    public static String localIP = "127.0.0.1";     // 默认服务器IP地址
    public static String nickname = "rayliu";      // 默认用户名
    public Socket socket;
    public static String msg;       // 存放本次发送的消息
    Vector<String> clientNames = new Vector<>();

    public static boolean ifConnected = false;

    private static String session_key = "";

    private static PrivateKey privateKey;

    private static PublicKey publicKey;

    private String privateKeyString;

    private String PublicKeyString;

    private static Map<String, String> publicKeyStringMap = new ConcurrentHashMap<>();

    private static Map<String, PublicKey> publicKeyMap = new ConcurrentHashMap<>();


    // 构造方法
    public Client() {
        init();
    }

    // 初始化方法：初始化图形界面
    private void init() {
        try{
            // panUp 区域初始化：流式面板，3个标签、3个输入框，2个按钮
            panUp.setLayout(new FlowLayout());
            panUp.add(lblLocalPort1);
            panUp.add(tfLocalPort1);
            panUp.add(lblLocalPort2);
            panUp.add(tfLocalPort2);
            panUp.add(lblLocalPort3);
            panUp.add(tfLocalPort3);
            tfLocalPort1.setText(localIP);
            tfLocalPort2.setText(String.valueOf(localPort));
            tfLocalPort3.setText(nickname);
            panUp.add(butStart);
            panUp.add(butStop);
            butStart.addActionListener(new linkServerHandlerStart());
            butStop.addActionListener(new linkServerHandlerStop());
            butStop.setEnabled(false);      // 断开服务器按钮的初始状态应该为 不可点击，只有连接服务器之后才能点击

            // 添加 Left
            taMsg.setEditable(false);
            panLeft.add(scroll);
            panLeft.setBorder(new TitledBorder("聊天——消息区"));
            scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

            // 添加 Middle
            panMid.setBorder(new TitledBorder("在线用户"));
            panMid.add(lstUsers);
            lstUsers.setVisibleRowCount(20);

            // 添加 Down
            // JTextField输入框 的回车事件默认存在，无需添加
            panDown.setLayout(new FlowLayout());
            panDown.add(lblLocalPort4);
            panDown.add(tfLocalPort4);
            tfLocalPort4.addActionListener(new SendHandler());
            panDown.add(lbSendUser);
            panDown.add(usersToSend);
            panDown.add(connButton);
            connButton.addActionListener(new connHandler());

            //加载个人公私钥和公钥环
            publicKeyMap = RSAUtils.getPublicKeyMap();
            publicKeyStringMap = RSAUtils.getPublicKeyStringMap();
            RSAUtils.genKeyPair(nickname);
            privateKey = RSAUtils.getPrivateKey();
            privateKeyString = RSAUtils.getKeyPair().get("PR");
            publicKey = RSAUtils.getPublicKey();
            PublicKeyString = RSAUtils.getKeyPair().get("PU");
        }catch (Exception e){
            e.printStackTrace();
        }





        // 图形界面的总体初始化 + 启动图形界面
        this.setTitle("客户端");
        this.add(panUp, BorderLayout.NORTH);
        this.add(panLeft, BorderLayout.WEST);
        this.add(panMid, BorderLayout.CENTER);
        this.add(panDown, BorderLayout.SOUTH);
        this.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        this.addWindowListener(new WindowHandler());
        this.setPreferredSize(new Dimension(800, 600));
        this.pack();
        this.setVisible(true);
    }

    //“连接服务器”按钮的动作事件监听处理类：
    private class linkServerHandlerStart implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            // 当点击"连接服务器"按钮之后，该按钮被禁用（不可重复点击）。同时"断开服务器按钮"被恢复使用
            butStart.setEnabled(false);
            butStop.setEnabled(true);
            localIP = tfLocalPort1.getText();
            localPort = Integer.parseInt(tfLocalPort2.getText());
            nickname = tfLocalPort3.getText();
            linkServer();   // 连接服务器
            Thread acceptThread = new Thread(new ReceiveRunnable());
            acceptThread.start();
        }
    }

    //“断开服务器”按钮的动作事件监听处理类
    private class linkServerHandlerStop implements ActionListener {
        /**
         * 当点击该按钮之后，断开服务器连接、清空图形界面所有数据
         */
        @Override
        public void actionPerformed(ActionEvent e) {
            taMsg.setText("");
            clientNames = new Vector<>();
            updateUsers();
            updateReceiver();
            cutServer();
            butStart.setEnabled(true);
            butStop.setEnabled(false);
        }
    }

    // 连接服务器的方法
    public void linkServer() {
        try {
            socket = new Socket(localIP, localPort);
            ifConnected = true;

        } catch (Exception ex) {
            taMsg.append("==== 连接服务器失败~ ====");
            ifConnected = false;
        }
    }

    // 收服务器消息的线程关联类
    private class ReceiveRunnable implements Runnable {
        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintStream(socket.getOutputStream());
                //当用户首次连接服务器时，应该向服务器发送自己的用户名、以及对用户名的签名用于身份验证
                Message userConn = new Message();
                userConn.setReceiverName("Server");
                userConn.setSenderName(nickname);
                userConn.setType(States.CONNECT);
                out.println(JSON.toJSONString(userConn));
                taMsg.append("——本人【" + nickname + "】成功连接到服务器......\n");
                Message getUserInfo = new Message();
                getUserInfo.setType(States.GET_USER_INFO);
                String getUserInfoJson = JSON.toJSONString(getUserInfo);
                out.println(getUserInfoJson);       // 向服务器发送"神秘代码"，请求 当前在线用户 列表
                while (true) {
                    String msgInJson = in.readLine();       // 读取服务器端的发送的数据
                    System.out.println(msgInJson);
                    Message msgReceived = JSON.parseObject(msgInJson,Message.class);
                    //服务器发来的消息类型是用户信息
                    if (msgReceived.getType().equals(States.USER_INFO)) {
                        msg = "更新在线用户列表";
                        clientNames.removeAllElements();
                        String[] split = msgReceived.getContent().split("\\|");
                        clientNames.addAll(Arrays.asList(split));
                        updateUsers();
                        updateReceiver();
                    }
                    //服务器发来的消息类型是会话密钥
                    //会话密钥由建立连接者生成，收到此消息表明有人要与自己建立连接
                    if(msgReceived.getType().equals(States.SESSION_KEY)){
                        String sender  =msgReceived.getSenderName();
                        //用自己的私钥解密,得到内部消息，包含会话密钥以及签名。
                        String sKey = RSAUtils.decrypt(msgReceived.getContent(),privateKeyString);
                        String sign = msgReceived.getSign();
                        //为当前消息生成消息摘要
                        String msgDigest = MessageDigestUtils.getMessageDigest(sKey);
                        //验证签名
                        boolean res = RSAUtils.verify(
                                msgDigest,
                                sign.getBytes("ISO-8859-1"),
                                publicKeyMap.get(sender));
                        if(res){
                            //设置session_key
                            session_key = sKey;
                            //通知发送方
                            Message returnMessage = new Message();
                            returnMessage.setSenderName(nickname);
                            returnMessage.setReceiverName(msgReceived.getSenderName());
                            returnMessage.setContent(nickname+"收到会话密钥");
                            returnMessage.setType(States.ACCEPTED);
                            out.println(JSON.toJSONString(returnMessage));
                            msg = "收到来自"+msgReceived.getSenderName()+"的会话密钥";
                        }
                    }
                    if(msgReceived.getType().equals(States.MESSAGE)){
                        //用会话密钥解密
                        String text = new String(
                                AESUtils.decrypt(msgReceived.getContent().getBytes("ISO-8859-1"),
                                session_key.getBytes()));
                        msg = text;
                    }
                    if(msgReceived.getType().equals(States.BROADCAST)){
                        msg = msgReceived.getContent();
                    }
                    if(msgReceived.getType().equals(States.ACCEPTED)){
                        msg = msgReceived.getContent();
                    }
                    // 此 if 语句作用：与服务器进行握手确认消息。
                    // 当接收到服务器端发送的确认离开请求bye 的时候，用户真正离线
                   if(msgReceived.getType().equals(States.SAY_GOODBYE)){
                       if(msgReceived.getReceiverName().equals(nickname)){
                           socket.close();
                           clientNames.remove(nickname);
                           updateUsers();
                           updateReceiver();
                           break;       // 终止线程
                       }
                   }
                    // 更新 "聊天——消息区" 信息
                    if(msgReceived.getType().equals(States.SESSION_KEY)){
                        taMsg.append("【"+nickname+"】"+msg+"\n");
                    }
                    else {
                        String msgWithName = "【"+msgReceived.getSenderName()+"】"+msg;
                        taMsg.append(msgWithName+ "\n");
                    }

                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // "发送消息文本框" 的动作事件监听处理类
    private class SendHandler implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            Message messageOut = new Message();
            messageOut.setSenderName(nickname);
            messageOut.setReceiverName((String)usersToSend.getSelectedItem());
            String plainText = tfLocalPort4.getText();
            byte[] bytes = AESUtils.encrypt(plainText.getBytes(), session_key.getBytes());
            try {
                String encrypt = new String(bytes, "ISO-8859-1");
                messageOut.setContent(encrypt);
                messageOut.setType(States.MESSAGE);
                String messageOut_Json = JSON.toJSONString(messageOut);
                out.println(messageOut_Json);
                tfLocalPort4.setText("");       // 当按下回车发送消息之后，输入框应该被清空
                msg = "【"+nickname+"】"+plainText;
                taMsg.append(msg + "\n");

            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    // 窗口关闭的动作事件监听处理类
    // 当用户点击 "x" 离开窗口时，也会向服务器发送 bye 请求，目的是为了同步更新数据。
    private class WindowHandler extends WindowAdapter {
        @Override
        public void windowClosing(WindowEvent e) {
            if(ifConnected){
                cutServer();
            }

        }
    }

    //连线按钮的事件监听器
    private class connHandler implements ActionListener{
        @Override
        public void actionPerformed(ActionEvent e) {
            if(session_key.equals("")){
                try {
                    session_key= AESUtils.genAesSecret();
                    String receiver = (String)usersToSend.getSelectedItem();
                    String msgDigest = MessageDigestUtils.getMessageDigest(session_key);
                    String sign = new String(RSAUtils.sign(msgDigest,privateKey),"ISO-8859-1");
                    Message conn = new Message();
                    conn.setType(States.SESSION_KEY);
                    conn.setReceiverName(receiver);
                    conn.setSenderName(nickname);
                    String PU = publicKeyStringMap.get(receiver);
                    String resultContent = RSAUtils.encrypt(session_key,PU );
                    conn.setContent(resultContent);
                    conn.setSign(sign);
                    out.println(JSON.toJSONString(conn));
                    taMsg.append("【"+nickname+"】"+"会话密钥已经发出\n");
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
    }




    private void cutServer() {
        Message bye = new Message();
        bye.setType(States.SAY_GOODBYE);
        bye.setSenderName(nickname);
        bye.setReceiverName("Server");
        bye.setContent("用户"+nickname+"离开");
        String bye_Json = JSON.toJSONString(bye);
        out.println(bye_Json);
        ifConnected = false;
    }

    // 更新 "在线用户列表" 的方法
    public void updateUsers() {
        panMid.setBorder(new TitledBorder("在线用户(" + clientNames.size() + "个)"));
        lstUsers.setListData(clientNames);
    }

    //更新选择发送下拉列表
    public void updateReceiver(){
        usersToSend.removeAllItems();
        for(String c: clientNames){
            usersToSend.addItem(c);
        }
    }









    // 主方法
    public static void main(String[] args) {
        new Client();
    }
}
