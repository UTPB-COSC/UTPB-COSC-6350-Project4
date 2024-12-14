import socket
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives import serialization
from Crypto import (aes_gcm_encrypt, aes_gcm_decrypt, derive_session_key)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555

# Set to track used nonces for replay protection
used_nonces = set()

def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            print(f"[INFO] Connecting to server...")
            client_socket.connect((SERVER_HOST, SERVER_PORT))

            # Step 1: Generate Client ECC Key Pair
            client_private_key = generate_private_key(SECP256R1())
            client_public_key = client_private_key.public_key()

            # Step 2: Receive Server Public Key
            server_public_bytes = client_socket.recv(1024)
            server_public_key = serialization.load_der_public_key(server_public_bytes)

            # Step 3: Send Client Public Key
            client_public_bytes = client_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.sendall(client_public_bytes)

            # Step 4: Derive Shared Secret and Session Key
            shared_secret = client_private_key.exchange(ECDH(), server_public_key)

            session_key = derive_session_key(shared_secret)

            # Step 5: Receive Handshake Confirmation
            confirmation = client_socket.recv(1024).decode()
            print(f"[INFO] Server: {confirmation}")

            # Step 6: Secure Communication
            messages = {"This is for Project 4.",
                        "Hello from Emmanuel Cardenas."}

            for message in messages:
                nonce, ciphertext, tag = aes_gcm_encrypt(message, session_key)
                client_socket.sendall(nonce + ciphertext + tag)
                print(f"[INFO] Sent encrypted message: {ciphertext.hex()}")

                # Receive responses
            for _ in range(3):
                packet = client_socket.recv(1024)
                if not packet:
                    break

                nonce = packet[:12]
                ciphertext = packet[12:-16]
                tag = packet[-16:]
                response = aes_gcm_decrypt(nonce, ciphertext, tag, session_key)
                print(f"[INFO] Server response (decrypted): {response}")

        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")

if __name__ == "__main__":
    tcp_client()
