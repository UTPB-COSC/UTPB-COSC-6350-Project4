import hmac
import hashlib
import os
from socket import socket, AF_INET, SOCK_STREAM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Constants
SSID = "TestSSID"
PSK = "TestPassword"
AP_MAC = "02:00:00:00:00:01"
CLIENT_MAC = "02:00:00:00:00:02"
PKE = "Pairwise key expansion"
PORT = 8080

# Helper functions
def generate_nonce():
    return os.urandom(32)

def pbkdf2(passphrase, ssid, iterations, key_len):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), iterations, key_len)

def prf(key, pke, data, length=64):
    i = 0
    R = b''
    while len(R) < length:
        hmacsha1 = hmac.new(key, (pke + chr(0).encode() + data + chr(i).encode()), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:length]

def calculate_mic(kck, message):
    return hmac.new(kck, message, hashlib.sha1).digest()

def aes_encrypt(key, data):
    nonce = os.urandom(16)  # 16-byte nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return nonce + ciphertext

def aes_decrypt(key, data):
    nonce, ciphertext = data[:16], data[16:]  # Extract nonce and ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded_data)

def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def ap_server():
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(('localhost', PORT))
    server_socket.listen(1)
    print("AP is ready and waiting for a connection...")
    conn, addr = server_socket.accept()
    print(f"Connected to client at {addr}")

    # Beacon frame simulation
    print(f"Sending beacon with SSID: {SSID}")
    conn.send(b"BEACON:" + SSID.encode())

    # Authentication and Association
    auth_request = conn.recv(4096)
    if auth_request == b"AUTH_REQUEST":
        print("Authentication request received")
        conn.send(b"AUTH_RESPONSE")
    assoc_request = conn.recv(4096)
    if assoc_request == b"ASSOC_REQUEST":
        print("Association request received")
        conn.send(b"ASSOC_RESPONSE")

    # Generate Anonce and send to client
    anonce = generate_nonce()
    conn.send(anonce)

    # Receive Snonce and MIC from client
    client_message = conn.recv(4096)
    snonce, received_mic = client_message[:32], client_message[32:]

    # Derive PTK and compare MICs
    pmk = pbkdf2(PSK, SSID, 4096, 32)
    key_data = min(AP_MAC, CLIENT_MAC).encode() + max(AP_MAC, CLIENT_MAC).encode() + \
               min(anonce, snonce) + max(anonce, snonce)
    ptk = prf(pmk, PKE.encode(), key_data)
    kck = ptk[:16]  # Key Confirmation Key
    kek = ptk[16:32]  # Key Encryption Key
    calculated_mic = calculate_mic(kck, anonce + snonce)

    if hmac.compare_digest(received_mic, calculated_mic):
        print("MIC verified successfully on AP side.")

    # Send M3 to client
    gtk = os.urandom(16)
    m3 = gtk + calculate_mic(kck, gtk)
    conn.send(m3)

    # Receive M4 and finalize
    m4 = conn.recv(4096)
    if hmac.compare_digest(m4[-16:], calculate_mic(kck, m4[:-16])):
        print("MIC verified successfully on AP side for M4.")
        print("Handshake complete, PTK and GTK installed.")

    # Simulate encrypted communication
    print("Starting encrypted communication...")
    encrypted_data = aes_encrypt(kek, b"Hello, Client!")
    print(f"Encrypted message sent to client: {encrypted_data.hex()}")
    conn.sendall(encrypted_data)

    client_response = conn.recv(4096)
    decrypted_response = aes_decrypt(kek, client_response)
    print(f"Decrypted message from client: {decrypted_response.decode()}")

    conn.close()

if __name__ == "__main__":
    ap_server()
