import socket
from my_crypto import generate_ecdh_key_pair, derive_shared_secret, derive_session_key, aes_decrypt, generate_hmac, aes_encrypt
from cryptography.hazmat.primitives import serialization
from datetime import datetime

HOST = '127.0.0.1'
PORT = 5555

def log(message, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{level}] [{timestamp}] {message}")

def tcp_client():
    log("===== WPA3 Secure Client =====")
    log("Starting the client...")

    try:
        # Generate client's ECDHE key pair
        log("Generating ECDHE key pair...")
        client_private_key, client_public_key = generate_ecdh_key_pair()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            log(f"Connecting to server at {HOST}:{PORT}...")
            client_socket.connect((HOST, PORT))
            log(f"Connected to server.")

            # Step 1: Receive server's public key
            log("--- Key Exchange Phase ---")
            log("Receiving server's public key...")
            server_public_bytes = client_socket.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_bytes)
            log("Server's public key received.")

            # Step 2: Send client's public key
            log("Sending client's public key to server...")
            client_socket.send(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            log("Client's public key sent.")

            # Step 3: Derive shared session key
            log("Deriving shared session key...")
            shared_secret = derive_shared_secret(client_private_key, server_public_key)
            session_key = derive_session_key(shared_secret)
            log("Session key established successfully.")
            #print("[DEBUG] Session Key Hash:", hashlib.sha256(session_key).hexdigest())

            # Step 4: Receive nonce from server
            log("--- Handshake Phase ---")
            log("Waiting for nonce from server...")
            nonce = client_socket.recv(1024)
            log("Nonce received.")

            # Step 5: Send HMAC to server
            log("Sending HMAC to server for handshake confirmation...")
            client_hmac = generate_hmac(session_key, nonce)
            client_socket.send(client_hmac)
            log("Sent HMAC to server.")
            log("Handshake completed.")

            # Step 6: Receive and decrypt multiple secure messages
            log("--- Secure Message Exchange ---")
            log("Waiting for secure messages from server...")
            for i in range(3):
                try:
                    log(f"Receiving encrypted message {i + 1}...")
    
                    # Receive message length
                    message_length_bytes = client_socket.recv(4)
                    while len(message_length_bytes) < 4:  # receive 4 bytes
                        chunk = client_socket.recv(4 - len(message_length_bytes))
                        if not chunk:
                            log("Failed to receive complete message length.", level="ERROR")
                            break
                        message_length_bytes += chunk
                    message_length = int.from_bytes(message_length_bytes, byteorder="big")
                    #log(f"Received message length: {message_length}", level="ERROR")
                    
                    # Receive encrypted message
                    encrypted_message = b""
                    while len(encrypted_message) < message_length:
                        chunk = client_socket.recv(message_length - len(encrypted_message))
                        if not chunk:
                            log("Incomplete message received.",level="ERROR")
                            break
                        encrypted_message += chunk

                    #print(f"[DEBUG] Encrypted message received: {encrypted_message}")

                    # Decrypt message
                    decrypted_message = aes_decrypt(encrypted_message, session_key)
                    log(f"Received: {decrypted_message.decode('utf-8')}")

                    # Respond to server
                    response = f"Response {i + 1} from client."
                    encrypted_response = aes_encrypt(response, session_key)
                    log(f"Sending encrypted response {i + 1} to server...")
                    client_socket.sendall(len(encrypted_response).to_bytes(4, byteorder="big"))
                    client_socket.sendall(encrypted_response)                  

                except UnicodeDecodeError as e:
                    log(f"UTF-8 decoding error: {e}",level = "ERROR")
                    #print("[DEBUG] Raw decrypted data (bytes):", decrypted_message)

                except Exception as e:
                    log(f"Failed to process message {i + 1}: {e}", level = "ERROR")

            log("All messages received and processed successfully.")

    except Exception as e:
        log(f"Client encountered an error: {e}", level = "ERROR")

if __name__ == "__main__":
    tcp_client()