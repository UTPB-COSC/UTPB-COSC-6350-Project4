import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.security.interfaces.*;

public class APServer {
    private static final int PORT = 12345;
    private static SecretKey sharedKey;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("AP Server is listening on port " + PORT);
            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");

            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Step 1: Generate AP nonce
            byte[] apNonce = new byte[16];
            new SecureRandom().nextBytes(apNonce);
            output.write(apNonce); // Send nonce to client
            System.out.println("AP Nonce sent.");

            // Step 2: Receive client nonce
            byte[] clientNonce = new byte[16];
            input.readFully(clientNonce);
            System.out.println("Client Nonce received.");

            // Step 3: Generate key pair and send public key to client
            KeyPair apKeyPair = generateKeyPair();
            byte[] apPublicKeyEncoded = apKeyPair.getPublic().getEncoded();
            output.writeInt(apPublicKeyEncoded.length);
            output.write(apPublicKeyEncoded);
            System.out.println("AP Public Key (hex): " + bytesToHex(apPublicKeyEncoded));

            // Step 4: Receive client's public key
            int clientPublicKeyLength = input.readInt();
            byte[] clientPublicKeyEncoded = new byte[clientPublicKeyLength];
            input.readFully(clientPublicKeyEncoded);
            System.out.println("Client Public Key (hex): " + bytesToHex(clientPublicKeyEncoded));

            PublicKey clientPublicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(clientPublicKeyEncoded));

            // Step 5: Generate shared secret using ECDHE
            sharedKey = generateSharedSecret(apKeyPair.getPrivate(), clientPublicKey);
            System.out.println("Shared Key (hex): " + bytesToHex(sharedKey.getEncoded()));

            // Step 6: Send encrypted confirmation
            String confirmationMessage = "Confirmation";
            byte[] encryptedConfirmation = encrypt(confirmationMessage.getBytes(), sharedKey);
            output.writeInt(encryptedConfirmation.length);
            output.write(encryptedConfirmation);
            System.out.println("Encrypted Confirmation (hex): " + bytesToHex(encryptedConfirmation));

            // Step 7: Receive client acknowledgment
            byte[] clientAck = new byte[128];
            int ackBytesRead = input.read(clientAck);
            System.out.println("Client acknowledgment received: " + new String(clientAck, 0, ackBytesRead));

            // Step 8: Send encrypted message to the client
            String message = "Hello from AP!";
            byte[] encryptedMessage = encrypt(message.getBytes(), sharedKey);
            output.writeInt(encryptedMessage.length);
            output.write(encryptedMessage);
            System.out.println("Encrypted Message (hex): " + bytesToHex(encryptedMessage));

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }

    private static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedData = cipher.doFinal(data);

        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);
        return result;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
