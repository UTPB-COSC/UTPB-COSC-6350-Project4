# Imported packages
import threading  # For handling multiple client connections
import socket  # For server socket communication
import hashlib  # For hashing the shared secret to create a session key
import time  # For adding delays between message sends
from Crypto import *

# Handles a connected client: performs handshake, sends/receives encrypted messages
def handle_client(conn, addr):
    try:
        print(f"[SERVER] Connection established with {addr}")

        # Step 1: Initialize Diffie-Hellman parameters (p, g) and generate AP's keys
        p = 23  # Prime number
        g = 5   # Generator
        ecdhe = ECDHE(p, g)

        # Step 2: Send AP's public key to the client
        conn.sendall(str(ecdhe.public_key).encode())
        print(f"[SERVER] Sent AP's public key: {ecdhe.public_key}")

        # Step 3: Receive client's public key
        client_public_key = int(conn.recv(1024).decode())
        print(f"[SERVER] Received client's public key: {client_public_key}")

        # Step 4: Compute the shared secret and derive the session key
        shared_secret = ecdhe.compute_shared_secret(client_public_key)
        session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
        print(f"[SERVER] Session key derived: {session_key}")

        # Step 5: Initialize nonce tracking for replay protection
        used_nonces = set()

        # Step 6: Encrypt and send messages to the client
        messages = [
            "Welcome to the secure AP, Client! This is Packet 1.",
            "Here is Packet 2 from the AP.",
            "Goodbye! This is the final packet from the AP."
        ]
        for message in messages:
            nonce, ciphertext = aes_gcm_encrypt(session_key, message)
            conn.sendall(nonce + ciphertext)  # Send combined nonce and ciphertext
            print(f"[SERVER] Sent encrypted message: {ciphertext.hex()}")
            time.sleep(1)  # Delay between messages

        # Step 7: Receive and decrypt messages from the client
        print("[SERVER] Waiting for encrypted messages from the client...")
        for _ in range(3):  # Expecting 3 messages from the client
            data = conn.recv(1024)
            if not data:
                break

            # Separate nonce and ciphertext
            nonce = data[:12]  # First 12 bytes are the nonce
            ciphertext = data[12:]  # Remaining bytes are the ciphertext

            # Replay protection: Check if nonce is reused
            if nonce in used_nonces:
                print("[SERVER] Replay attack detected! Nonce reused.")
                break
            used_nonces.add(nonce)

            # Decrypt the received message
            decrypted_message = aes_gcm_decrypt(session_key, nonce, ciphertext)
            print(f"[SERVER] Decrypted message from client: {decrypted_message}")

    except Exception as e:
        print(f"[SERVER] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Connection closed with {addr}")

# Starts the AP server to listen for incoming client connections
def start_server(host='127.0.0.1', port=5001):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"[SERVER] Server is listening on {host}:{port}")

            while True:
                conn, addr = server_socket.accept()
                print(f"[SERVER] Accepted new connection from {addr}")
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
    except Exception as e:
        print(f"[SERVER] Server error: {e}")

# Catches the main thread
if __name__ == "__main__":
    start_server()
