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

def client():
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('localhost', PORT))

    # Receive beacon
    beacon = client_socket.recv(4096)
    print(f"Received beacon: {beacon.decode()}")

    # Authentication and Association
    client_socket.send(b"AUTH_REQUEST")
    auth_response = client_socket.recv(4096)
    if auth_response == b"AUTH_RESPONSE":
        print("Authentication successful")

    client_socket.send(b"ASSOC_REQUEST")
    assoc_response = client_socket.recv(4096)
    if assoc_response == b"ASSOC_RESPONSE":
        print("Association successful")

    # Receive Anonce from AP
    anonce = client_socket.recv(4096)

    # Generate Snonce and derive PTK
    snonce = generate_nonce()
    pmk = pbkdf2(PSK, SSID, 4096, 32)
    key_data = min(AP_MAC, CLIENT_MAC).encode() + max(AP_MAC, CLIENT_MAC).encode() + \
               min(anonce, snonce) + max(anonce, snonce)
    ptk = prf(pmk, PKE.encode(), key_data)
    kck = ptk[:16]  # Key Confirmation Key
    kek = ptk[16:32]  # Key Encryption Key

    # Send Snonce and MIC to AP
    mic = calculate_mic(kck, anonce + snonce)
    client_socket.send(snonce + mic)

    # Receive M3 from AP
    m3 = client_socket.recv(4096)
    gtk = m3[:-16]
    received_mic = m3[-16:]
    if hmac.compare_digest(received_mic, calculate_mic(kck, gtk)):
        print("MIC verified successfully on client side for M3.")

    # Send M4 to AP
    ack_flag = b"ACK"
    m4 = ack_flag + calculate_mic(kck, ack_flag)
    client_socket.send(m4)

    print("Handshake complete, PTK and GTK installed.")

    # Simulate encrypted communication
    encrypted_data = client_socket.recv(4096)
    print(f"Encrypted message received from server: {encrypted_data.hex()}")
    decrypted_message = aes_decrypt(kek, encrypted_data)
    print(f"Decrypted message from server: {decrypted_message.decode()}")

    encrypted_response = aes_encrypt(kek, b"Hello, AP!")
    client_socket.send(encrypted_response)

    client_socket.close()

if __name__ == "__main__":
    client()
