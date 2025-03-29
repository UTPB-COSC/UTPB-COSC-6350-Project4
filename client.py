import socket
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Load server public key
def load_public_key():
    with open("server_public_key.pem", "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Generate a random session key for AES encryption
def generate_session_key():
    return os.urandom(32)  # AES-256 key (32 bytes)

# Client setup
HOST = '127.0.0.1'
PORT = 12345
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print("Client connected to server.")

try:
    server_public_key = load_public_key()
    print("Client loaded server public key.")

    session_key = generate_session_key()
    print(f"Generated session key: {session_key} (Length: {len(session_key)})")

    # Encrypt the session key using the server's public key
    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Encrypted session key: {encrypted_session_key}")

    # Base64 encode the encrypted session key before sending
    encrypted_session_key_b64 = base64.b64encode(encrypted_session_key)
    print(f"Base64-encoded encrypted session key: {encrypted_session_key_b64}")

    # Send encrypted session key to server
    client_socket.send(encrypted_session_key_b64)

except Exception as e:
    print(f"Error during communication: {e}")
finally:
    client_socket.close()
