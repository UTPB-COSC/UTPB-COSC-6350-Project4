# Imported packages
import socket  # For client socket communication
import hashlib  # For hashing the shared secret to create a session key
import time  # For adding delays between message sends
from Crypto import *

# Connects to the server (AP), performs handshake, and exchanges encrypted messages
def start_client(server_host='127.0.0.1', server_port=5001):
    try:
        # Step 1: Initialize Diffie-Hellman parameters (p, g) and generate Client's keys
        p = 23  # Prime number
        g = 5   # Generator
        ecdhe = ECDHE(p, g)

        # Establish a connection to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_host, server_port))
            print(f"[CLIENT] Connected to server at {server_host}:{server_port}")

            # Step 2: Receive AP's public key
            ap_public_key = int(client_socket.recv(1024).decode())
            print(f"[CLIENT] Received AP's public key: {ap_public_key}")

            # Step 3: Send Client's public key to the AP
            client_socket.sendall(str(ecdhe.public_key).encode())
            print(f"[CLIENT] Sent Client's public key: {ecdhe.public_key}")

            # Step 4: Compute the shared secret and derive the session key
            shared_secret = ecdhe.compute_shared_secret(ap_public_key)
            session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
            print(f"[CLIENT] Session key derived: {session_key}")

            # Step 5: Receive and decrypt messages from the AP
            print("[CLIENT] Waiting to receive encrypted messages from the server...")
            for _ in range(3):  # Expecting 3 packets from the AP
                data = client_socket.recv(1024)
                if not data:
                    break

                # Separate nonce and ciphertext
                nonce = data[:12]  # First 12 bytes are the nonce
                ciphertext = data[12:]  # Remaining bytes are the ciphertext

                # Decrypt the message
                decrypted_message = aes_gcm_decrypt(session_key, nonce, ciphertext)
                print(f"[CLIENT] Decrypted message from server: {decrypted_message}")
                time.sleep(1)  # Delay for readability

            # Step 6: Encrypt and send messages back to the AP
            messages = [
                "Hello, Server! This is a response from the Client.",
                "Client message number 2.",
                "Final message from the Client."
            ]
            for message in messages:
                nonce, ciphertext = aes_gcm_encrypt(session_key, message)
                client_socket.sendall(nonce + ciphertext)  # Send combined nonce and ciphertext
                print(f"[CLIENT] Sent encrypted message: {ciphertext.hex()}")
                time.sleep(1)  # Delay between sends

    except Exception as e:
        print(f"[CLIENT] Error during communication: {e}")

# Catches the main thread
if __name__ == "__main__":
    start_client()
