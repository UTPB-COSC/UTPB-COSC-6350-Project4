import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.net.*;
import java.io.*;
import java.util.*;

public class WPA2Client {
    private static final String PMK = "0123456789abcdef0123456789abcdef"; // Pre-shared key
    private static final String CLIENT_MAC = "aa:bb:cc:dd:ee:ff";
    private static final String SERVER_ADDRESS = "localhost";
    private static final String AP_MAC = "00:11:22:33:44:55";

    private static final int SERVER_PORT = 12345;

    @SuppressWarnings("resource")
    public static void main(String[] args) {
        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            System.out.println("\n");
            System.out.println("********************************************************************************");
            System.out.println("Connected to the Server");
            System.out.println("Address: " + SERVER_ADDRESS);
            System.out.println("Port: " + SERVER_PORT);
            System.out.println("********************************************************************************");

            
            // Step 1: Receive ANonce
            String aNonceHex = in.readUTF();
            byte[] aNonce = hexToBytes(aNonceHex);
            System.out.println("\n");
            System.out.println("Received ANonce: " + aNonceHex);
            System.out.println("\n");

            // Step 2: Generate SNonce and send with MIC
            byte[] sNonce = generateNonce();
            System.out.println("SNONCE: " + bytesToHex(sNonce));
            System.out.println("\n");

            byte[] ptk = derivePTK(PMK.getBytes(), aNonce, sNonce, AP_MAC.getBytes(), CLIENT_MAC.getBytes());
            System.out.println("PTK (KCK): " + bytesToHex(Arrays.copyOfRange(ptk, 0, 16)));
            System.out.println("PTK (KEK): " + bytesToHex(Arrays.copyOfRange(ptk, 16, 32)));
            System.out.println("PTK (TEK): " + bytesToHex(Arrays.copyOfRange(ptk, 32, 48)));
            System.out.println("\n");

            byte[] mic = calculateMIC(Arrays.copyOfRange(ptk, 0, 16), "Message2".getBytes());
            out.writeUTF(bytesToHex(sNonce) + ":" + bytesToHex(mic));
            System.out.println("SNONCE: " + bytesToHex(sNonce));
            System.out.println("MIC: " + bytesToHex(mic));
            System.out.println("Sent SNonce and MIC");
            System.out.println("\n");

            // Step 3: Receive GTK and verify MIC
            String message3 = in.readUTF();
            String[] parts = message3.split(":");
            byte[] encryptedGTK = hexToBytes(parts[0]);
            byte[] receivedMIC = hexToBytes(parts[1]);

            System.out.println("\n");
            System.out.println("MIC Verification");
            System.out.println("MIC Calculation Input (Key): " + bytesToHex(Arrays.copyOfRange(ptk, 0, 16)));
            System.out.println("Encrypted GTK (Data): " + bytesToHex(encryptedGTK));

            byte[] calculatedMIC = calculateMIC(Arrays.copyOfRange(ptk, 0, 16), encryptedGTK);
            
            System.out.println("Calculated MIC: " + bytesToHex(calculatedMIC));
            System.out.println("Received MIC: " + bytesToHex(receivedMIC));
            
            if (!MessageDigest.isEqual(receivedMIC, calculatedMIC)) {
                System.out.println("MIC verification failed. Handshake aborted.");
                return;
            }
            System.out.println("MIC verified successfully.");
            System.out.println("\n");

            // Decrypt GTK
            @SuppressWarnings("unused")
            byte[] gtk = decryptGTK(encryptedGTK, Arrays.copyOfRange(ptk, 16, 32));
            System.out.println("\n");
            System.out.println("GTK Decryption");
            System.out.println("GTK decrypted successfully.");
            System.out.println("Decrypted GTK: " + bytesToHex(gtk));
            System.out.println("\n");

            System.out.println("\n");
            System.out.println("ACK");

            // Step 4: Send ACK
            out.writeUTF("ACK");
            System.out.println("Sent ACK. Handshake completed successfully.");
            System.out.println("\n");

            // Receive encrypted message
            String encryptedMessageHex = in.readUTF();
            byte[] encryptedMessage = hexToBytes(encryptedMessageHex);
            String decryptedMessage = decryptMessage(encryptedMessage, Arrays.copyOfRange(ptk, 32, 48));
            System.out.println("Received and decrypted message: " + decryptedMessage);
            System.out.println(" ");
        
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        return nonce;
    }

    private static byte[] derivePTK(byte[] pmk, byte[] aNonce, byte[] sNonce, byte[] apMac, byte[] clientMac) throws NoSuchAlgorithmException {
        byte[] ptkData = new byte[16 + 32 + 32 + 6 + 6];
        System.arraycopy("Pairwise key expansion".getBytes(), 0, ptkData, 0, 16);
        System.arraycopy(apMac, 0, ptkData, 16, 6);
        System.arraycopy(clientMac, 0, ptkData, 22, 6);
        System.arraycopy(aNonce, 0, ptkData, 28, 32);
        System.arraycopy(sNonce, 0, ptkData, 60, 32);
        return PRF(pmk, ptkData, 48);
    }
    

    private static byte[] PRF(byte[] key, byte[] prefix, int len) throws NoSuchAlgorithmException {
        byte[] result = new byte[len];
        int offset = 0;
        int i = 0;
        while (offset < len) {
            Mac hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA1");
            try {
                hmac.init(keySpec);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
            hmac.update(prefix);
            hmac.update((byte) i);
            byte[] digest = hmac.doFinal();
            System.arraycopy(digest, 0, result, offset, Math.min(digest.length, len - offset));
            offset += digest.length;
            i++;
        }
        return result;
    }

    private static byte[] calculateMIC(byte[] kck, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA1");
        SecretKeySpec keySpec = new SecretKeySpec(kck, "HmacSHA1");
        hmac.init(keySpec);
        return hmac.doFinal(data);
    }

    private static byte[] decryptGTK(byte[] encryptedGTK, byte[] kek) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(kek, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(encryptedGTK);
    }

    private static String decryptMessage(byte[] encryptedMessage, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] iv = Arrays.copyOfRange(encryptedMessage, 0, 16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Arrays.copyOfRange(encryptedMessage, 16, encryptedMessage.length));
        return new String(decrypted);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
