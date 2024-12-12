# Imported packages
import random  # For generating private keys in Diffie-Hellman
import os  # For generating random nonces
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # For AES-GCM encryption/decryption

# ECDHE Class for Diffie-Hellman Key Exchange
class ECDHE:
    def __init__(self, p, g):
        # Prime number and generator used for key exchange
        self.p = p
        self.g = g
        # Generate a random private key
        self.private_key = random.randint(2, self.p - 1)
        # Compute the public key to share with the other party
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        # Compute the shared secret using the other party's public key
        return pow(other_public_key, self.private_key, self.p)

# Encrypts a plaintext message using AES-GCM
def aes_gcm_encrypt(session_key, plaintext):
    key = bytes.fromhex(session_key)  # Convert session key from hex to bytes
    nonce = os.urandom(12)  # Generate a random 12-byte nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

# Decrypts a ciphertext using AES-GCM
def aes_gcm_decrypt(session_key, nonce, ciphertext):
    key = bytes.fromhex(session_key)  # Convert session key from hex to bytes
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
