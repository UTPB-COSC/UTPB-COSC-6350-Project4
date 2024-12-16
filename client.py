import socket
from my_crypto import generate_ecdh_key_pair, derive_shared_secret, derive_session_key, aes_decrypt, generate_hmac, aes_encrypt
from cryptography.hazmat.primitives import serialization
from datetime import datetime

HOST = '127.0.0.1'
PORT = 5555

def log(message, level="CLIENT"):
    print(f"[{level}] {message}")

def tcp_client():
    print(f"{"*" * 50}")
    print("Secure Client Initialized")
    print(f"{"*" * 50}")

    try:
        log("Setting up secure communication...")
        client_private_key, client_public_key = generate_ecdh_key_pair()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            log(f"Connecting to server at {HOST}:{PORT}...")
            client_socket.connect((HOST, PORT))
            log("Connection established with server.")

            print(f"{"*" * 50}")
            print("Key Exchange Phase")
            print(f"{"*" * 50}")
            log("Receiving server's public key...")
            server_public_bytes = client_socket.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_bytes)
            log("Server's public key successfully received.")

            log("Sending client's public key to server...")
            client_socket.send(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            log("Client's public key successfully sent.")

            log("Generating shared session key...")
            shared_secret = derive_shared_secret(client_private_key, server_public_key)
            session_key = derive_session_key(shared_secret)
            log("Shared session key established.")

            
            print(f"{"*" * 50}")
            print("Handshake Phase")
            print(f"{"*" * 50}")
            log("Awaiting nonce from server...")
            nonce = client_socket.recv(1024)
            log("Nonce received from server.")

            log("Verifying connection integrity...")
            client_hmac = generate_hmac(session_key, nonce)
            client_socket.send(client_hmac)
            log("Handshake completed successfully.")

            
            print(f"{"*" * 50}")
            print("Secure Communication Phase")
            print(f"{"*" * 50}")
            for i in range(3):
                try:
                    log(f"Waiting for secure message {i + 1} from server...")
                    message_length_bytes = client_socket.recv(4)
                    message_length = int.from_bytes(message_length_bytes, byteorder="big")
                    encrypted_message = b""
                    while len(encrypted_message) < message_length:
                        encrypted_message += client_socket.recv(message_length - len(encrypted_message))

                    decrypted_message = aes_decrypt(encrypted_message, session_key)
                    log(f"Server: {decrypted_message.decode('utf-8')}")

                    response = f"Acknowledged message {i + 1} from server."
                    encrypted_response = aes_encrypt(response, session_key)
                    client_socket.sendall(len(encrypted_response).to_bytes(4, byteorder="big"))
                    client_socket.sendall(encrypted_response)
                except Exception as e:
                    log(f"Error processing message {i + 1}: {e}", level="ERROR")

            log("All messages exchanged successfully.")

            
            print(f"{"*" * 50}")
            print("Final Communication Phase")
            print(f"{"*" * 50}")
            while True:
                user_input = input("Enter message for server (type 'exit' to close): ")
                if user_input.lower() == "exit":
                    log("Closing connection as per user request.")
                    break
                encrypted_message = aes_encrypt(user_input, session_key)
                client_socket.sendall(len(encrypted_message).to_bytes(4, byteorder="big"))
                client_socket.sendall(encrypted_message)
                log("Message sent to server.")

    except Exception as e:
        log(f"Client encountered an error: {e}", level="ERROR")

if __name__ == "__main__":
    tcp_client()