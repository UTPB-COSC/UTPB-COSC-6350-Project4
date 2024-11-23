import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.security.interfaces.*;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;
    private static SecretKey sharedKey;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, PORT)) {
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Step 1: Receive AP nonce
            byte[] apNonce = new byte[16];
            input.readFully(apNonce);
            System.out.println("AP Nonce received.");

            // Step 2: Generate client nonce and send to AP
            byte[] clientNonce = new byte[16];
            new SecureRandom().nextBytes(clientNonce);
            output.write(clientNonce);
            System.out.println("Client Nonce sent.");

            // Step 3: Generate key pair and send public key to AP
            KeyPair clientKeyPair = generateKeyPair();
            byte[] clientPublicKeyEncoded = clientKeyPair.getPublic().getEncoded();
            output.writeInt(clientPublicKeyEncoded.length);
            output.write(clientPublicKeyEncoded);
            System.out.println("Client Public Key (hex): " + bytesToHex(clientPublicKeyEncoded));

            // Step 4: Receive AP's public key
            int apPublicKeyLength = input.readInt();
            byte[] apPublicKeyEncoded = new byte[apPublicKeyLength];
            input.readFully(apPublicKeyEncoded);
            System.out.println("AP Public Key (hex): " + bytesToHex(apPublicKeyEncoded));

            PublicKey apPublicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(apPublicKeyEncoded));

            // Step 5: Generate shared secret using ECDHE
            sharedKey = generateSharedSecret(clientKeyPair.getPrivate(), apPublicKey);
            System.out.println("Shared Key (hex): " + bytesToHex(sharedKey.getEncoded()));

            // Step 6: Receive encrypted confirmation
            int confirmationLength = input.readInt();
            byte[] encryptedConfirmation = new byte[confirmationLength];
            input.readFully(encryptedConfirmation);
            System.out.println("Encrypted Confirmation (hex): " + bytesToHex(encryptedConfirmation));

            // Step 7: Send acknowledgment
            String acknowledgment = "Acknowledged";
            output.write(acknowledgment.getBytes());
            System.out.println("Client acknowledgment sent.");

            // Step 8: Receive encrypted message
            int messageLength = input.readInt();
            byte[] encryptedMessage = new byte[messageLength];
            input.readFully(encryptedMessage);
            System.out.println("Encrypted Message (hex): " + bytesToHex(encryptedMessage));

            byte[] iv = new byte[16];
            System.arraycopy(encryptedMessage, 0, iv, 0, iv.length);
            byte[] encryptedData = new byte[encryptedMessage.length - iv.length];
            System.arraycopy(encryptedMessage, iv.length, encryptedData, 0, encryptedData.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sharedKey, ivSpec);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            System.out.println("Decrypted Message: " + new String(decryptedData));
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
