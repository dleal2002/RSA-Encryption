# **RSA Encryption Client-Server Demo**

This program demonstrates how **RSA encryption** can be used in a simple client-server communication system.

---

## 🔑 Server (`server_RSA.java`)
- Generates an **RSA key pair** (public and private keys).  
- Listens on **port 2025** for incoming client connections.  
- Shares its **public key** with each connected client.  
- Receives encrypted messages from the client.  
- **Decrypts messages** using its private key and displays them.  
- Sends the **decrypted message back** to the client as confirmation.  

---

## 💻 Client (`client_RSA.java`)
- Connects to the server on **port 2025**.  
- Retrieves the server’s **public key**.  
- Uses the public key to **encrypt user input** before sending it to the server.  
- Sends the encrypted message securely across the network.  
- Receives and displays the **decrypted response** from the server.  

---

## 🔐 Key Concept
This setup illustrates the core principle of **RSA encryption**:  
> Data encrypted with a **public key** can only be decrypted with the corresponding **private key**.  

This ensures secure communication between the client and the server.
