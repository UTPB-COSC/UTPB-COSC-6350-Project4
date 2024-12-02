from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC



def generate_ecdh_key_pair():
    """
    Generate an ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key pair.
    - Returns the private key and the corresponding public key.
    - The private key is used to compute a shared secret.
    - The public key is shared with the peer during the handshake.
    """
    private_key = ec.generate_private_key(ec.SECP256R1()) # Generate a private key using SECP256R1 curve
    public_key = private_key.public_key() # Derive the public key from the private key
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    """Derive a shared secret using ECDHE."""
    return private_key.exchange(ec.ECDH(), peer_public_key)

def derive_session_key(shared_secret, salt=b"WPA3", info=b"WPA3 Handshake"):
    """Derive a session key using HKDF (HMAC-based Key Derivation Function)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(), # SHA-256 as the underlying hash function
        length=32, # Output key length (32 bytes)
        salt=salt, # Cryptographic salt
        info=info # Context information
    )
    return hkdf.derive(shared_secret)

# Function to encrypt a string using AES
def aes_encrypt(plaintext, key):
    iv = os.urandom(16) # Generate a random 16-byte IV

    # Create cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor() # Create encryptor

    # Pad the plaintext to be AES block size (16 bytes) compatible
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV concatenated with the ciphertext (to be used in decryption)
    return iv + ciphertext

# Function to decrypt the AES ciphertext
def aes_decrypt(ciphertext, key):
    # Extract the IV from the first 16 bytes
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # Create cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create decryptor
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError:
        raise ValueError("Decryption failed due to invalid padding.")

    # Return the original plaintext as a string
    return unpadded_data

def decompose_byte(byte):
    crumbs = [(byte >> (i * 2)) & 0b11 for i in range(4)] # Extract each 2-bit crumb
    return crumbs[::-1] # Reverse the order to match the desired representation

def recompose_byte(crumbs):
    byte = 0 # Initialize the byte to 0
    for i, crumb in enumerate(crumbs[::-1]): # Process crumbs in reverse order
        byte |= (crumb & 0b11) << (i * 2) # Shift and combine the crumbs into the byte
    return byte

# Generate an HMAC (Hash-based Message Authentication Code) for the given data
def generate_hmac(key, data):
    hmac = HMAC(key, hashes.SHA256()) # Use SHA-256 for HMAC
    hmac.update(data) # Update with the data
    return hmac.finalize()

# Verify the HMAC for the given data.
def verify_hmac(key, data, hmac_to_verify):
    hmac = HMAC(key, hashes.SHA256()) # Use SHA-256 for HMAC
    hmac.update(data) # Update with the data
    hmac.verify(hmac_to_verify)