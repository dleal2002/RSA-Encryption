import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.util.Base64;

public class server_RSA {
    // Variables for server's public and private keys
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public server_RSA() throws Exception {
        generateKeyPair();
    }

    private void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();

        System.out.println("Server Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("Private Key = Secret");
    }

    public static void main(String[] args) {
        try {
            // Instantiate server and generate keys
            server_RSA server = new server_RSA();

            // Send server's public key (Base64 encoded)
            String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(server.publicKey.getEncoded());
            System.out.println("Server Public Key (sent to clients): " + serverPublicKeyBase64);

            ServerSocket serverSocket = new ServerSocket(2025);
            serverSocket.setReuseAddress(true);
            System.out.println("Port created, waiting for connections...");

            while (true) {
                Socket client = serverSocket.accept();
                System.out.println("New client connected: " + client.getInetAddress().getHostAddress());
                ClientHandler clientSock = new ClientHandler(client, server.privateKey, server.publicKey);
                new Thread(clientSock).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final PrivateKey privateKey;
        // Will be passed from server
        private final PublicKey serverPublicKey;  

        public ClientHandler(Socket socket, PrivateKey privateKey, PublicKey serverPublicKey) {
            this.clientSocket = socket;
            this.privateKey = privateKey;
            this.serverPublicKey = serverPublicKey;
        }

        public void run() {
            try {
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                // Read client's public key
                String clientPublicKeyBase64 = in.readLine();
                byte[] clientKeyBytes = Base64.getDecoder().decode(clientPublicKeyBase64);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

                // Send server's public key
                String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
                out.println(serverPublicKeyBase64);
                System.out.println("Sent server public key to client.");

                String line;
                while ((line = in.readLine()) != null) {
                    String decryptedMessage;
                    try {
                        decryptedMessage = decrypt(line);
                    } catch (BadPaddingException e) {
                        System.out.println("BadPaddingException: " + e.getMessage());
                        continue;
                    }

                    if ("reverse".equalsIgnoreCase(decryptedMessage.trim())) {
                        String prompt = "type any word for server to reverse it";
                        out.println(encrypt(prompt, clientPublicKey));
                        String wordEncrypted = in.readLine();
                        if (wordEncrypted == null) break;
                        String word;
                        try {
                            word = decrypt(wordEncrypted);
                        } catch (BadPaddingException e) {
                            System.out.println("BadPaddingException during reverse word decryption: " + e.getMessage());
                            continue;
                        }
                        String reversed = new StringBuilder(word).reverse().toString();
                        String reply = "Reversed: " + reversed;
                        out.println(encrypt(reply, clientPublicKey));
                        continue;
                    }

                    if ("prime".equalsIgnoreCase(decryptedMessage.trim())) {
                        String prompt = "Type an integer between 1 - 100";
                        out.println(encrypt(prompt, clientPublicKey));
                        String numberEncrypted = in.readLine();
                        if (numberEncrypted == null) break;
                        String numberStr;
                        try {
                            numberStr = decrypt(numberEncrypted);
                        } catch (BadPaddingException e) {
                            System.out.println("BadPaddingException during number decryption: " + e.getMessage());
                            continue;
                        }
                        int number;
                        try {
                            number = Integer.parseInt(numberStr.trim());
                        } catch (NumberFormatException e) {
                            String errorMsg = "Invalid number format.";
                            out.println(encrypt(errorMsg, clientPublicKey));
                            continue;
                        }
                        if (number < 1 || number > 100) {
                            String errorMsg = "Number out of range. Please choose between 1 and 100.";
                            out.println(encrypt(errorMsg, clientPublicKey));
                            continue;
                        }
                        String primesList = getPrimesUpTo(number);
                        String reply = "Primes up to " + number + ": " + primesList;
                        out.println(encrypt(reply, clientPublicKey));
                        continue;
                    }

                    if ("exit".equalsIgnoreCase(decryptedMessage.trim())) {
                        System.out.println("Ending connection...");
                        String reply = "please wait...";
                        out.println(encrypt(reply, clientPublicKey));
                        break;
                    }

                    System.out.println("Received: " + decryptedMessage);
                    String reply = "Echo: " + decryptedMessage;
                    out.println(encrypt(reply, clientPublicKey));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        
        //RSA functions - decrypt 
        private String decrypt(String encryptedMessage) throws Exception {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }
        
        //RSA functions - Encrypt 

        private String encrypt(String message, PublicKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }
        
        
        //Prime function - get all numbers from 1 - user input
        public static String getPrimesUpTo(int max) {
            StringBuilder primes = new StringBuilder();
            for (int i = 2; i <= max; i++) {
                if (isPrime(i)) {
                    primes.append(i).append(", ");
                }
            }
            if (primes.length() > 0)
                primes.setLength(primes.length() - 2);
            return primes.toString();
        }

        private static boolean isPrime(int num) {
            if (num < 2) return false;
            for (int i = 2; i <= Math.sqrt(num); i++) {
                if (num % i == 0) return false;
            }
            return true;
        }
    }
}
