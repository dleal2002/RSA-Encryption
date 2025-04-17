import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

class server_RSA {
	//variables for public and private keys 
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    //throws error if key generation = fails
    public server_RSA() throws Exception {
        generateKeyPair();
    }
    
    //key generation 
    private void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        //keys created successfully 
        System.out.println("Server Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.printf("Private Key = Secret\n");
    }

    public static void main(String[] args) {
    	//create server
    	server_RSA server;
        try {
        	//create server socket with port
            server = new server_RSA();
            ServerSocket serverSocket = new ServerSocket(2025);   //Can change port number if you want
            serverSocket.setReuseAddress(true);
            System.out.printf("Port created, waiting for connections...\n");

            //wait for connections
            while (true) {
                Socket client = serverSocket.accept();
                System.out.println("New client connected: " + client.getInetAddress().getHostAddress());
                
                // Pass the public and private key to the ClientHandler
                ClientHandler clientSock = new ClientHandler(client, server.publicKey, server.privateKey);
                new Thread(clientSock).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //make thread
    //this allows other computers to connect to same server using 1 port number (2025)
    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        public ClientHandler(Socket socket, PublicKey publicKey, PrivateKey privateKey) {
            this.clientSocket = socket;
            this.publicKey = publicKey;
            this.privateKey = privateKey; // Store the private key in an instance variable
        }
        
        //encrypt/decrypt logic
        public void run() {
            PrintWriter out = null;
            BufferedReader in = null;
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                //wait for connections...
                
                // Send the public key to the client
                out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                
                //line = any client message that might be send (encrypted)
                String line;
                
                //Decrypt message 
                while ((line = in.readLine()) != null) {
                	
                    System.out.printf("New Message! Decoding...\n" );
                    // Decrypt the received message using the private key
                    String decryptedMessage = decrypt(line);
                    
                    //print message 
                    System.out.printf("Cient Message: %s\n\n", decryptedMessage);
                    
                    //send decrypted message to client!
                    out.println(decryptedMessage);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    if (out != null) {
                        out.close();
                    }
                    if (in != null) {
                        in.close();
                        clientSocket.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private String decrypt(String encryptedMessage) throws Exception {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey); // Use the stored private key
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }
    }
}


