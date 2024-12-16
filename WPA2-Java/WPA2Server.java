import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.net.*;
import java.io.*;
import java.util.*;

public class WPA2Server {
    private static final String PMK = "0123456789abcdef0123456789abcdef"; // Pre-shared key
    private static final String CLIENT_MAC = "aa:bb:cc:dd:ee:ff";
    private static final String AP_MAC = "00:11:22:33:44:55";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                System.out.println("\n");
                System.out.println("WPA2 AP started on port " + PORT);
                System.out.println("\n");


                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    new ClientHandler(clientSocket).start();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private Socket clientSocket;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            try {
                DataInputStream in = new DataInputStream(clientSocket.getInputStream());
                DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

                // Step 1: Generate ANonce
                byte[] aNonce = generateNonce();
                out.writeUTF(bytesToHex(aNonce));
                System.out.println("Sent ANonce: " + bytesToHex(aNonce));

                // Step 2: Receive SNonce and MIC
                String message2 = in.readUTF();
                String[] parts = message2.split(":");
                byte[] sNonce = hexToBytes(parts[0]);
                byte[] receivedMIC = hexToBytes(parts[1]);
                System.out.println("Received SNonce: " + bytesToHex(sNonce));
                
                System.out.println("PMK: " + bytesToHex(PMK.getBytes()));


                // Derive PTK
                System.out.println("\n");

                byte[] ptk = derivePTK(PMK.getBytes(), aNonce, sNonce, AP_MAC.getBytes(), CLIENT_MAC.getBytes());
                System.out.println("PTK (KCK): " + bytesToHex(Arrays.copyOfRange(ptk, 0, 16)));
                System.out.println("PTK (KEK): " + bytesToHex(Arrays.copyOfRange(ptk, 16, 32)));
                System.out.println("PTK (TEK): " + bytesToHex(Arrays.copyOfRange(ptk, 32, 48)));
                System.out.println("\n");

                // Verify MIC
                System.out.println("\n");

                byte[] data = "Message2".getBytes();
                System.out.println("MIC Calculation Input (Key): " + bytesToHex(Arrays.copyOfRange(ptk, 0, 16)));

                byte[] calculatedMIC = calculateMIC(Arrays.copyOfRange(ptk, 0, 16), data);
                System.out.println("Calculated MIC: " + bytesToHex(calculatedMIC));
                System.out.println("Received MIC: " + bytesToHex(receivedMIC));

                if (!MessageDigest.isEqual(receivedMIC, calculatedMIC)) {
                    System.out.println("MIC verification failed. Handshake aborted.");
                    return;
                }
                System.out.println("MIC verified successfully.");

                System.out.println("\n");

                // Step 3: Send GTK and MIC
                byte[] gtk = generateGTK();
                byte[] encryptedGTK = encryptGTK(gtk, Arrays.copyOfRange(ptk, 16, 32));
                System.out.println("Encrypted GTK " + bytesToHex(encryptedGTK));
                byte[] mic3 = calculateMIC(Arrays.copyOfRange(ptk, 0, 16), encryptedGTK);
                out.writeUTF(bytesToHex(encryptedGTK) + ":" + bytesToHex(mic3));
                System.out.println("MIC :" + bytesToHex(mic3));
                System.out.println("Sent encrypted GTK and MIC");
                System.out.println("\n");


                // Step 4: Receive ACK
                String ack = in.readUTF();
                if ("ACK".equals(ack)) {
                    System.out.println("\n");

                    System.out.println("Received ACK. Handshake completed successfully.");
                    // Send encrypted message
                    String message = "HELLO FROM SERVER!";
                    byte[] encryptedMessage = encryptMessage(message.getBytes(), Arrays.copyOfRange(ptk, 32, 48));
                    out.writeUTF(bytesToHex(encryptedMessage));
                    System.out.println("Sent encrypted message: " + message);
                }

                clientSocket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
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

    private static byte[] generateGTK() {
        SecureRandom random = new SecureRandom();
        byte[] gtk = new byte[32];
        random.nextBytes(gtk);
        return gtk;
    }

    private static byte[] encryptGTK(byte[] gtk, byte[] kek) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(kek, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(gtk);
    }

    private static byte[] encryptMessage(byte[] message, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(message);
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
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
