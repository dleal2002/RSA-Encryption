import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Scanner;

// Client class
class client_RSA {
    private PublicKey publicKey;

    public static void main(String[] args) {
    	//connect to server (using port 2025)
        try (Socket socket = new Socket("localhost", 2025)) {
            System.out.println("Sucessfully connected to server!");
        	
            // Reading from server
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Receiving public key from server
            String publicKeyBase64 = in.readLine();
            System.out.println("Public Key From Server: " + publicKeyBase64 + "\n\n");
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            
            // Writing to server
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner sc = new Scanner(System.in);
            String line = null;
            System.out.printf("Type a message for server: ");

            while (!"exit".equalsIgnoreCase(line)) {
                // Reading input from user
                line = sc.nextLine();

                // Encrypt user input using public key
                System.out.printf("Encrytpting message...\n");
                String encryptedMessage = encrypt(line, publicKey);

                // Sending the encrypted message to server
                out.println(encryptedMessage);
                out.flush();
                System.out.printf("DONE! Sent to server!\n\n");


                // Display server reply
                System.out.println("Server replied: " + in.readLine());
            }
            sc.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}