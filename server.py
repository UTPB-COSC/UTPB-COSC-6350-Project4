import socket
from cryptography.hazmat.primitives import serialization
from my_crypto import generate_ecdh_key_pair, derive_shared_secret, derive_session_key, aes_encrypt, verify_hmac, aes_decrypt
import os
import time
from datetime import datetime

HOST = '0.0.0.0'
PORT = 5555

def log(message, level="SERVER"):
    print(f"[{level}] {message}")

def handle_client(conn):
    log("New client connected.")

    try:

        print(f"{"*" * 50}")
        print("Key Exchange Phase")
        print(f"{"*" * 50}")
        log("Generating server's ECDHE key pair...")
        server_private_key, server_public_key = generate_ecdh_key_pair()

        log("Sending server's public key to client...")
        conn.send(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        log("Server's public key sent.")

        log("Receiving client's public key...")
        client_public_bytes = conn.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)
        log("Client's public key successfully received.")

        log("Deriving shared session key...")
        shared_secret = derive_shared_secret(server_private_key, client_public_key)
        session_key = derive_session_key(shared_secret)
        log("Shared session key established.")


        print(f"{"*" * 50}")
        print("Handshake Phase")
        print(f"{"*" * 50}")
        log("Generating and sending nonce to client...")
        nonce = os.urandom(16)
        conn.send(nonce)
        log("Nonce sent to client.")

        log("Receiving HMAC from client...")
        client_hmac = conn.recv(1024)
        verify_hmac(session_key, nonce, client_hmac)
        log("Handshake verified successfully.")


        print(f"{"*" * 50}")
        print("Secure Communication Phase")
        print(f"{"*" * 50}")
        for i in range(3):
            payload = f"Secure message {i + 1} from server."
            encrypted_message = aes_encrypt(payload, session_key)
            log(f"Sending secure message {i + 1} to client...")
            conn.sendall(len(encrypted_message).to_bytes(4, byteorder="big"))
            conn.sendall(encrypted_message)

            log(f"Awaiting response {i + 1} from client...")
            response_length_bytes = conn.recv(4)
            response_length = int.from_bytes(response_length_bytes, byteorder="big")
            encrypted_response = b""
            while len(encrypted_response) < response_length:
                encrypted_response += conn.recv(response_length - len(encrypted_response))

            decrypted_response = aes_decrypt(encrypted_response, session_key)
            log(f"Client Response {i + 1}: {decrypted_response.decode('utf-8')}")

        log("All secure messages exchanged successfully.")


        print(f"{"*" * 50}")
        print("Final Communication Phase")
        print(f"{"*" * 50}")
        while True:
            log("Waiting for final message from client...")
            message_length_bytes = conn.recv(4)
            if not message_length_bytes:
                break

            message_length = int.from_bytes(message_length_bytes, byteorder="big")
            encrypted_message = b""
            while len(encrypted_message) < message_length:
                encrypted_message += conn.recv(message_length - len(encrypted_message))

            decrypted_message = aes_decrypt(encrypted_message, session_key).decode('utf-8')
            if decrypted_message.lower() == "exit":
                log("Client requested to close the connection.")
                break
            log(f"Client: {decrypted_message}")

    except Exception as e:
        log(f"Error during client communication: {e}", level="ERROR")
    finally:
        conn.close()
        log("Connection with client closed.")


def start_server():
    print(f"{"*" * 50}")
    print("Secure Server Initialized")
    print(f"{"*" * 50}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        log(f"Server listening on {HOST}:{PORT}.")

        while True:
            log("Awaiting client connection...")
            conn, addr = server_socket.accept()
            log(f"Client connected from {addr}.")
            handle_client(conn)

if __name__ == "__main__":
    start_server()
