import socket, json, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class WPAServer:
    def _init_(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.anonce = os.urandom(32)
        self.session_key = None
    
    def derive_pmk(self, password, ssid):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode() + ssid.encode())
        return digest.finalize()
    
    def generate_ptk(self, pmk, snonce):
        ptk_info = b"PTK-Key-Generation"
        hkdf = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=ptk_info)
        key_material = self.anonce + snonce + pmk
        return hkdf.derive(key_material)
    
    def encrypt_data(self, data):
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.session_key[:32]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return {'iv': base64.b64encode(iv).decode(), 'data': base64.b64encode(encrypted).decode()}
    
    def decrypt_data(self, encrypted_dict):
        iv = base64.b64decode(encrypted_dict['iv'])
        encrypted = base64.b64decode(encrypted_dict['data'])
        cipher = Cipher(algorithms.AES(self.session_key[:32]), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()
    
    def run(self, password="MySecurePassword", ssid="TestNetwork"):
        print(f"WPA3 AP starting on {self.host}:{self.port}")
        print(f"Using network: {ssid}")
        client, addr = self.socket.accept()
        print(f"Client connected: {addr}")
        try:
            public_bytes = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            msg1 = {'type': 'M1', 'anonce': base64.b64encode(self.anonce).decode(), 'public_key': base64.b64encode(public_bytes).decode()}
            client.send(json.dumps(msg1).encode())
            msg2 = json.loads(client.recv(4096).decode())
            snonce = base64.b64decode(msg2['snonce'])
            client_public_key = serialization.load_der_public_key(base64.b64decode(msg2['public_key']))
            shared_key = self.private_key.exchange(ec.ECDH(), client_public_key)
            pmk = self.derive_pmk(password, ssid)
            self.session_key = self.generate_ptk(pmk, snonce)
            msg3 = {'type': 'M3', **self.encrypt_data("Handshake confirmation")}
            client.send(json.dumps(msg3).encode())
            msg4 = json.loads(client.recv(4096).decode())
            confirmation = self.decrypt_data(msg4)
            if confirmation != "Handshake confirmed":
                raise Exception("Handshake failed!")
            print("Handshake completed successfully!")
            while True:
                encrypted_msg = json.loads(client.recv(4096).decode())
                if not encrypted_msg:
                    break
                msg = self.decrypt_data(encrypted_msg)
                print(f"Received: {msg}")
                response = f"Echo: {msg}"
                client.send(json.dumps(self.encrypt_data(response)).encode())
                if msg.lower() == "quit":
                    break
        except Exception as e:
            print(f"Error during handshake: {e}")
        finally:
            client.close()
            self.socket.close()

if _name_ == "_main_":
    server = WPAServer()
    server.run()
