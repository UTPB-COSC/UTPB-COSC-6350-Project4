import socket
from cryptography.hazmat.primitives import serialization
from my_crypto import generate_ecdh_key_pair, derive_shared_secret, derive_session_key, aes_encrypt, verify_hmac, aes_decrypt
import os
import time
from datetime import datetime

HOST = '0.0.0.0'
PORT = 5555

def log(message, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{level}] [{timestamp}] {message}")

def handle_client(conn):
    log("Handling new client connection...")

    try:
        log("--- Key Exchange Phase ---")
        # Generate server's ECDHE key pair
        log("Generating ECDHE key pair...")
        server_private_key, server_public_key = generate_ecdh_key_pair()

        # Step 1: Send server's public key
        log("Sending server's public key to client...")
        conn.send(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        log("Server's public key sent.")

        # Step 2: Receive client's public key
        log("Receiving client's public key...")
        client_public_bytes = conn.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)
        log("Client's public key received.")

        # Step 3: Derive shared session key
        log("Deriving shared session key...")
        shared_secret = derive_shared_secret(server_private_key, client_public_key)
        session_key = derive_session_key(shared_secret)
        log("Session key established.")

        # Step 4: Send nonce to client
        log("--- Handshake Phase ---")
        log("Generating and sending nonce to client...")
        nonce = os.urandom(16)
        conn.send(nonce)
        log("Nonce sent.")

        # Step 5: Receive and verify client's HMAC
        log("Waiting for client's HMAC...")
        client_hmac = conn.recv(1024)
        log("Received client's HMAC.")
        verify_hmac(session_key, nonce, client_hmac)
        log("Handshake successful!")

        # Step 6: Exchange multiple secure messages
        log("--- Secure Message Exchange ---")
        for i in range(3):
            payload = f"Secure message {i + 1} from server."
            encrypted_message = aes_encrypt(payload, session_key)

            # Send the length of the encrypted message
            log(f"Sending encrypted message {i + 1}")
            conn.settimeout(5)
            try:
                conn.sendall(len(encrypted_message).to_bytes(4, byteorder="big"))
                conn.sendall(encrypted_message)
                #print(f"[DEBUG] Sent encrypted message: {encrypted_message}")
            except socket.timeout:
                log("Timeout occurred while sending the encrypted message.", level="ERROR")

            time.sleep(0.1) # Delay to ensure smooth communication

            # Server receives encrypted messages from the client
            try:
                log(f"Waiting for encrypted response {i + 1} from client...")
    
                # Receive response length
                response_length_bytes = conn.recv(4)
                if not response_length_bytes:
                    log("Failed to receive response length.", level="ERROR")
                    continue
                response_length = int.from_bytes(response_length_bytes, byteorder="big")
                
                # Receive encrypted response
                encrypted_response = b""
                while len(encrypted_response) < response_length:
                    chunk = conn.recv(response_length - len(encrypted_response))
                    if not chunk:
                        log("Incomplete response received.", level="ERROR")
                        break
                    encrypted_response += chunk

                #print(f"[DEBUG] Encrypted response received: {encrypted_response}")

                # Decrypt response
                decrypted_response = aes_decrypt(encrypted_response, session_key)
                log(f"Received response {i+1} from client: {decrypted_response.decode('utf-8')}")

            except Exception as e:
                log(f"Failed to process client response {i + 1}: {e}", level = "ERROR")

    except Exception as e:
        log(f"An error occurred while handling client: {e}", level="ERROR")
    finally:
        conn.close()
        log("Client connection closed.")

def start_server():
    log("===== WPA3 Secure Server =====")
    log("Starting the server...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        log(f"Server listening on {HOST}:{PORT}...")

        while True:
            log("Waiting for a new client to connect...")
            conn, addr = server_socket.accept()
            log(f"Connection established with {addr}.")
            handle_client(conn)

if __name__ == "__main__":
    start_server()