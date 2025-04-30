import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Scanner;

class client_RSA {
	//variables to store private keys
    private PrivateKey privateKey;
 // Client's public key
    private PublicKey publicKey; 
 // Variable to hold server's public key
    private PublicKey serverPublicKey; 

    public static void main(String[] args) {
        client_RSA client = new client_RSA();
        client.startClient();
    }

    private void startClient() {
        // Generate key pair here
        try {
            // Generate client's key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            //need public and private keys for RSA encryption 
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
            //Client port needs to match server port
            try (Socket socket = new Socket("localhost", 2025)) {
                System.out.println("Successfully connected to server!");

                // Reading from server
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

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

                // Messaging loop
                Scanner sc = new Scanner(System.in);
                // Initialize line to avoid NullPointerException
                String line = ""; 
                //MENU: server functionality
                System.out.printf("\nType 'reverse' to reverse words\nType 'prime' to find prime numbers between 0 - YOUR INPUT\nType 'exit' to quit");
                while (!"exit".equalsIgnoreCase(line)) {
                    line = sc.nextLine();

                    // Encrypt the message using the server's public key
                    String encryptedMessage = encrypt(line, serverPublicKey);
                    out.println(encryptedMessage);

                    // Display server reply
                    String encryptedReply = in.readLine();
                    if (encryptedReply != null) {
                        System.out.println("Server replied: " + decrypt(encryptedReply));
                    }
                }
                sc.close();
                System.out.printf("Sucessfully Disconnected From Server!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //RSA functions - Encryption 
    private String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    //RSA functions - Decryption 

    private String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        return new String(cipher.doFinal(decryptedBytes));
    }
}
