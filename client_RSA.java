import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

class client_RSA extends JFrame {
    // variables to store private keys
    private PrivateKey privateKey;
    // Client's public key
    private PublicKey publicKey;
    // Variable to hold server's public key
    private PublicKey serverPublicKey;

    private JTextArea displayArea;
    private JTextField inputField;
    private JButton sendButton;

    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    public client_RSA() {
        super("RSA Client");
        initComponents();
        startClient();
    }

    private void initComponents() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 400);
        setLayout(new BorderLayout());

        displayArea = new JTextArea();
        displayArea.setEditable(false);
        displayArea.setLineWrap(true);
        displayArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(displayArea);
        add(scrollPane, BorderLayout.CENTER);

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputField = new JTextField();
        sendButton = new JButton("Send");

        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        add(inputPanel, BorderLayout.SOUTH);

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        inputField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });
    }

    private void startClient() {
        new Thread(() -> {
            try {
                // Generate client's key pair
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();
                // need public and private keys for RSA encryption
                publicKey = keyPair.getPublic();
                privateKey = keyPair.getPrivate();

                // Client port needs to match server port
                socket = new Socket("localhost", 2025);
                displayMessage("Successfully connected to server!");

                // Reading from server
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                // Send the client's public key to the server
                String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                out.println(publicKeyBase64);

                // Read server's public key (the server's public key should be sent back after the client sends its public key)
                String serverPublicKeyBase64 = in.readLine();
                // Assume server sends its public key as a response
                byte[] serverKeyBytes = Base64.getDecoder().decode(serverPublicKeyBase64);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                serverPublicKey = keyFactory.generatePublic(keySpec);

                // Display the menu
                displayMessage("\nType 'reverse' to reverse words\nType 'prime' to find prime numbers between 0 - YOUR INPUT\nType 'exit' to quit");

                // Start a thread to listen for server replies
                listenForServerReplies();

            } catch (Exception e) {
                e.printStackTrace();
                displayMessage("Error connecting to server: " + e.getMessage());
            }
        }).start();
    }

    private void sendMessage() {
        String line = inputField.getText();
        if (line.isEmpty() || out == null) {
            return;
        }

        inputField.setText(""); // Clear the input field

        if ("exit".equalsIgnoreCase(line)) {
            displayMessage("You: " + line);
            try {
                String encryptedMessage = encrypt(line, serverPublicKey);
                out.println(encryptedMessage);
                // Wait for server's reply before closing
                // The listening thread will handle the final server message
            } catch (Exception e) {
                e.printStackTrace();
                displayMessage("Error sending message: " + e.getMessage());
            }
            // The listening thread will close the socket when it receives the exit confirmation
        } else {
            displayMessage("You: " + line);
            try {
                String encryptedMessage = encrypt(line, serverPublicKey);
                out.println(encryptedMessage);
            } catch (Exception e) {
                e.printStackTrace();
                displayMessage("Error sending message: " + e.getMessage());
            }
        }
    }

    private void listenForServerReplies() {
        new Thread(() -> {
            try {
                String encryptedReply;
                while ((encryptedReply = in.readLine()) != null) {
                    String decryptedReply = decrypt(encryptedReply);
                    displayMessage("Server replied: " + decryptedReply);
                    if ("please wait...".equalsIgnoreCase(decryptedReply.trim())) {
                        // Server is indicating the connection is closing
                        break;
                    }
                }
            } catch (IOException e) {
                // Connection closed or error
                displayMessage("Connection to server closed.");
            } catch (Exception e) {
                e.printStackTrace();
                displayMessage("Error decrypting server reply: " + e.getMessage());
            } finally {
                try {
                    if (socket != null && !socket.isClosed()) {
                        socket.close();
                        displayMessage("Successfully Disconnected From Server!");
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private void displayMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            displayArea.append(message + "\n");
        });
    }

    // RSA functions - Encryption
    private String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // RSA functions - Decryption
    private String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        return new String(cipher.doFinal(decryptedBytes));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new client_RSA().setVisible(true);
        });
    }
}
