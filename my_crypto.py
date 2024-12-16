import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

def derive_session_key(shared_secret, salt=b"WPA3", info=b"WPA3 Handshake"):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret)

def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError:
        raise ValueError("Invalid Padding, Decryption failed.")
    return unpadded_data

def decompose_byte(byte):
    crumbs = [(byte >> (i * 2)) & 0b11 for i in range(4)]
    return crumbs[::-1]

def recompose_byte(crumbs):
    byte = 0
    for i, crumb in enumerate(crumbs[::-1]):
        byte |= (crumb & 0b11) << (i * 2)
    return byte

def generate_hmac(key, data):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(data)
    return hmac.finalize()

def verify_hmac(key, data, hmac_to_verify):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(data)
    hmac.verify(hmac_to_verify)