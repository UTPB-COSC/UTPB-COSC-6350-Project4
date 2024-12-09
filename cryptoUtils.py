import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from constants import WPA3Constants

class CryptoUtils:
    @staticmethod
    def generate_nonce():
        return secrets.token_bytes(WPA3Constants.NONCE_LENGTH)

    @staticmethod
    def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
        material = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=WPA3Constants.PTK_LENGTH,
            salt=None,
            info=b'WPA3 PTK Expansion',
            backend=default_backend()
        )
        return hkdf.derive(pmk + material)

    @staticmethod
    def encrypt_message(key, message):
        if not isinstance(message, bytes):
            message = message.encode()
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key[:32]),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        associated_data = len(message).to_bytes(8, byteorder='big')
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return associated_data + iv + encryptor.tag + ciphertext

    @staticmethod 
    def decrypt_message(key, encrypted_data):
        associated_data = encrypted_data[:8]
        iv = encrypted_data[8:20]
        tag = encrypted_data[20:36]
        ciphertext = encrypted_data[36:]
        cipher = Cipher(
            algorithms.AES(key[:32]),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()
