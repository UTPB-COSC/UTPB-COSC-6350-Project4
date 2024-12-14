import socket
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives import serialization
from Crypto import aes_gcm_encrypt, aes_gcm_decrypt, derive_session_key

# Set to track used nonces for replay protection
used_nonces = set()

HOST = '127.0.0.1'
PORT = 5555

def handle_client(conn):
    try:
        # ECC Key Exchange Steps
        server_private_key = generate_private_key(SECP256R1())
        server_public_key = server_private_key.public_key()

        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_public_bytes)

        client_public_bytes = conn.recv(1024)
        client_public_key = serialization.load_der_public_key(client_public_bytes)

        shared_secret = server_private_key.exchange(ECDH(), client_public_key)
        session_key = derive_session_key(shared_secret)

        conn.sendall(b"Handshake successful!")

        # Secure Communication: Receive messages
        for _ in range(3):
            packet = conn.recv(1024)
            if not packet:
                break

            # Extract nonce, ciphertext, and tag
            nonce = packet[:12]
            ciphertext = packet[12:-16]
            tag = packet[-16:]

            if nonce in used_nonces:
                print("[WARNING] Replay attack detected! Packet dropped.")
                continue

            used_nonces.add(nonce)  # Mark nonce as used
            decrypted_message = aes_gcm_decrypt(nonce, ciphertext, tag, session_key)
            print(f"[INFO] Received (decrypted): {decrypted_message}")

            # Send a response
            response = f"Server received: {decrypted_message}"
            nonce, ciphertext, tag = aes_gcm_encrypt(response, session_key)
            conn.sendall(nonce + ciphertext + tag)

    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")
    finally:
        conn.close()
        print("[INFO] Connection closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[INFO] Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            print(f"[INFO] Connection from {addr}")
            handle_client(conn)

if __name__ == "__main__":
    start_server()
