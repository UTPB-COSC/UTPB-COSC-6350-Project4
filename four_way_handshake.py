import threading
import time
import random
import socket
import hashlib

# Basic RSA Implementation
def is_prime(num):
    """Check if a number is prime."""
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_prime(bits=8):
    """Generate a random prime number of a specified bit size."""
    while True:
        num = random.randint(2**(bits-1), 2**bits)
        if is_prime(num):
            return num

def extended_gcd(a, b):
    """Extended Euclidean algorithm to find the greatest common divisor."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def mod_inverse(a, m):
    """Find the modular inverse of a under modulo m."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_rsa_keys(bits=8):
    """Generate RSA public and private keys."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose e
    e = 65537  # Common choice for e
    while extended_gcd(e, phi_n)[0] != 1:
        e = random.randint(2, phi_n - 1)
    
    # Calculate d
    d = mod_inverse(e, phi_n)
    
    # Return public and private keys
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encrypt(public_key, plaintext):
    """Encrypt plaintext using the RSA public key."""
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """Decrypt ciphertext using the RSA private key."""
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext

# Simplified AES-like encryption and decryption
def xor_bytes(byte_data, key):
    """Perform XOR between byte data and key (simplified)."""
    return [b ^ key for b in byte_data]

def simplify_aes_encrypt(session_key, plaintext):
    """Encrypt the plaintext using a simplified AES-like approach."""
    rounds = 5
    byte_data = [ord(c) for c in plaintext]
    
    # First round, XOR the plaintext with the session key
    byte_data = xor_bytes(byte_data, session_key)
    
    # Simplified rounds (just XORing and rotating)
    for _ in range(rounds):
        byte_data = xor_bytes(byte_data, session_key)
        byte_data = byte_data[1:] + byte_data[:1]  # Rotate left by 1
    
    return byte_data

def simplify_aes_decrypt(session_key, encrypted_data):
    """Decrypt the encrypted data using the same simplified AES-like approach."""
    rounds = 5
    byte_data = encrypted_data
    
    # Reverse rounds (rotate and XOR back)
    for _ in range(rounds):
        byte_data = byte_data[-1:] + byte_data[:-1]  # Rotate right by 1
        byte_data = xor_bytes(byte_data, session_key)
    
    # Final XOR with the session key
    byte_data = xor_bytes(byte_data, session_key)
    
    return ''.join(chr(b) for b in byte_data)

# ECDHE Class for Diffie-Hellman Key Exchange
class ECDHE:
    def __init__(self, p, g):
        self.p = p  # Shared prime
        self.g = g  # Shared generator
        self.private_key = random.randint(2, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        """Compute shared secret using other's public key."""
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return shared_secret

def ap_server():
    try:
        host = '127.0.0.1'  # Localhost
        port = 5001        # Arbitrary non-privileged port
        p = 23              # Shared prime
        g = 5               # Shared generator

        # Create ECDHE object and RSA keypair
        ecdhe = ECDHE(p, g)
        public_rsa, private_rsa = generate_rsa_keys(bits=8)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of the address
            server_socket.bind((host, port))
            server_socket.listen()
            print("Server (AP) waiting for connection...")

            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")

                # Step 1: Send AP's public key (ECDHE)
                conn.sendall(str(ecdhe.public_key).encode())
                print(f"AP public key sent: {ecdhe.public_key}")

                # Step 2: Receive client's public key (ECDHE) and send AP's RSA public key
                client_public_key = int(conn.recv(1024).decode())
                print(f"AP received client public key: {client_public_key}")
                
                # AP receives the client's RSA public key
                client_rsa_public_key = conn.recv(1024).decode()  # Receive the client's RSA public key
                print(f"AP received client RSA public key: {client_rsa_public_key}")
                conn.sendall(str(public_rsa).encode())  # Send RSA public key
                print(f"AP sent RSA public key")

                # Step 3: Compute shared secret and session key
                shared_secret = ecdhe.compute_shared_secret(client_public_key)
                print(f"AP shared secret: {shared_secret}")
                session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()  # Hash to create session key
                print(f"AP session key established: {session_key}")

                # Step 4: Encrypt and send a few packets to the client
                messages = ["Hello, Client. This is packet 1.", "This is packet 2.", "Final message/packet from AP."]
                for message in messages:
                    encrypted_msg = simplify_aes_encrypt(int(session_key[:4], 16), message)
                    conn.sendall(bytes(encrypted_msg))
                    print(f"AP encrypted message sent: {encrypted_msg}")
                    time.sleep(1)  # Wait for the client to process
            print("Server task complete!")
    except Exception as e:
        print(f"Error in ap_server: {e}")

def client():
    try:
        host = '127.0.0.1'  # Localhost
        port = 5001        # Same port as the server
        p = 23              # Shared prime
        g = 5               # Shared generator

        # Create ECDHE object and RSA keypair
        ecdhe = ECDHE(p, g)
        public_rsa, private_rsa = generate_rsa_keys(bits=8)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))

            # Step 1: Receive AP's public key (ECDHE)
            ap_public_key = int(client_socket.recv(1024).decode())
            print(f"Client received AP public key: {ap_public_key}")

            # Step 2: Send client's public key (ECDHE) and receive RSA public key from AP
            client_socket.sendall(str(ecdhe.public_key).encode())
            print(f"Client public key sent: {ecdhe.public_key}")
            # Client sends RSA public key to AP
            client_socket.sendall(str(public_rsa).encode())  # Send the client's RSA public key to AP
            print(f"Client sent RSA public key")

            # Receive AP's RSA public key
            ap_public_rsa = client_socket.recv(1024)
            print(f"Client received AP's RSA public key: {ap_public_rsa.decode()}")

            # Step 3: Compute shared secret and session key
            shared_secret = ecdhe.compute_shared_secret(ap_public_key)
            print(f"Client shared secret: {shared_secret}")
            session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()  # Hash to create session key
            print(f"Client session key established: {session_key}")

            # Step 4: Receive and decrypt messages
            for _ in range(3):
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:  # Check if the received message is empty
                    print("No message received. Connection might be closed.")
                    break
                decrypted_msg = simplify_aes_decrypt(int(session_key[:4], 16), list(encrypted_message))
                print(f"Client decrypted message: {decrypted_msg}")
                time.sleep(2)

        print("Client task complete!")
    except Exception as e:
        print(f"Error in client: {e}")

if __name__ == "__main__":
    server_thread = threading.Thread(target=ap_server)
    server_thread.start()

    client()

    server_thread.join()  # Ensure the server thread finishes before main exits
    print("Main program complete.")
