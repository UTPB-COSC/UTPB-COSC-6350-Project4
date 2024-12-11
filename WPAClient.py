import socket, json, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class WPAClient:
    def _init_(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.snonce = os.urandom(32)
        self.session_key = None
    
    def derive_pmk(self, password, ssid):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode() + ssid.encode())
        return digest.finalize()
    
    def generate_ptk(self, pmk, anonce):
        ptk_info = b"PTK-Key-Generation"
        hkdf = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=ptk_info)
        key_material = anonce + self.snonce + pmk
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
    
    def connect(self, password="MySecurePassword", ssid="TestNetwork"):
        print(f"Connecting to AP at {self.host}:{self.port}")
        print(f"Network: {ssid}")
        try:
            self.socket.connect((self.host, self.port))
            msg1 = json.loads(self.socket.recv(4096).decode())
            anonce = base64.b64decode(msg1['anonce'])
            ap_public_key = serialization.load_der_public_key(base64.b64decode(msg1['public_key']))
            public_bytes = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            msg2 = {'type': 'M2', 'snonce': base64.b64encode(self.snonce).decode(), 'public_key': base64.b64encode(public_bytes).decode()}
            self.socket.send(json.dumps(msg2).encode())
            shared_key = self.private_key.exchange(ec.ECDH(), ap_public_key)
            pmk = self.derive_pmk(password, ssid)
            self.session_key = self.generate_ptk(pmk, anonce)
            msg3 = json.loads(self.socket.recv(4096).decode())
            confirmation = self.decrypt_data(msg3)
            if confirmation != "Handshake confirmation":
                raise Exception("Invalid confirmation from AP")
            msg4 = self.encrypt_data("Handshake confirmed")
            self.socket.send(json.dumps(msg4).encode())
            print("Handshake completed successfully!")
            while True:
                message = input("Enter message (or 'quit' to exit): ")
                self.socket.send(json.dumps(self.encrypt_data(message)).encode())
                encrypted_response = json.loads(self.socket.recv(4096).decode())
                response = self.decrypt_data(encrypted_response)
                print(f"Server response: {response}")
                if message.lower() == "quit":
                    break
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.socket.close()

if _name_ == "_main_":
    client = WPAClient()
    client.connect()
