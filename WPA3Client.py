import socket
from cryptoUtils import CryptoUtils
from constants import WPA3Constants
from WPA3AP import WPA3AP

class WPA3Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.pmk = b'0' * WPA3Constants.PMK_LENGTH
        self.mac = b'CLIENT_MAC'
    def connect(self):
        try:
            self.sock.connect((WPA3Constants.HOST, WPA3Constants.PORT))
            anonce = self.sock.recv(WPA3Constants.NONCE_LENGTH)
            snonce = CryptoUtils.generate_nonce()
            self.sock.send(snonce)
            self.sock.send(self.mac)
            ptk = CryptoUtils.derive_ptk(self.pmk, anonce, snonce, b'AP_MAC_ADDR', self.mac)
            response = self.sock.recv(1024)
            if response == b'PTK_READY':
                self.sock.send(b'PTK_INSTALLED')
                print("Four-way handshake completed successfully!")
                for i in range(3):
                    try:
                        message = f"Test message {i+1} from client"
                        encrypted_msg = CryptoUtils.encrypt_message(ptk, message)
                        self.sock.send(len(encrypted_msg).to_bytes(4, byteorder='big'))
                        self.sock.send(encrypted_msg)
                        msg_len = int.from_bytes(self.sock.recv(4), byteorder='big')
                        encrypted_response = self.sock.recv(msg_len)
                        decrypted_response = CryptoUtils.decrypt_message(ptk, encrypted_response)
                        print(f"Received from AP: {decrypted_response.decode()}")
                    except Exception as e:
                        print(f"Error in message exchange: {e}")
                        break                 
        finally:
            self.sock.close()
