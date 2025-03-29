import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Load private key
def load_private_key():
    with open("private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Decrypt session key
def decrypt_session_key(encrypted_session_key, private_key):
    try:
        decrypted_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted session key: {decrypted_key} (Length: {len(decrypted_key)})")
        return decrypted_key
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise

# Server setup
HOST = '127.0.0.1'
PORT = 12345
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Server listening on port {PORT}...")

# Handle client connection
client_socket, client_address = server_socket.accept()
print(f"Connection established with {client_address}")

try:
    private_key = load_private_key()
    print("Server loaded private key.")

    # Receive encrypted session key from client
    encrypted_session_key_b64 = client_socket.recv(4096)
    print(f"Server received Base64-encoded session key: {encrypted_session_key_b64}")

    encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
    print(f"Server Base64-decoded encrypted session key: {encrypted_session_key}")

    # Decrypt the session key
    session_key = decrypt_session_key(encrypted_session_key, private_key)

except Exception as e:
    print(f"Error during communication: {e}")
finally:
    client_socket.close()
    server_socket.close()
