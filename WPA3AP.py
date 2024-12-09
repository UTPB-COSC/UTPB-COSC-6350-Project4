import socket
import threading
from cryptoUtils import CryptoUtils
from constants import WPA3Constants

class WPA3AP:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((WPA3Constants.HOST, WPA3Constants.PORT))
        self.sock.listen(1)
        self.pmk = b'0' * WPA3Constants.PMK_LENGTH
        self.mac = b'AP_MAC_ADDR'
        
    def handle_client(self, client_socket, client_address):
        try:
            anonce = CryptoUtils.generate_nonce()
            client_socket.send(anonce)
            snonce = client_socket.recv(WPA3Constants.NONCE_LENGTH)
            client_mac = client_socket.recv(len(self.mac))
            ptk = CryptoUtils.derive_ptk(self.pmk, anonce, snonce, self.mac, client_mac)
            client_socket.send(b'PTK_READY')
            response = client_socket.recv(1024)
            if response == b'PTK_INSTALLED':
                print("Four-way handshake completed successfully!")
                for i in range(3):
                    try:
                        msg_len = int.from_bytes(client_socket.recv(4), byteorder='big')
                        encrypted_data = client_socket.recv(msg_len)
                        decrypted_msg = CryptoUtils.decrypt_message(ptk, encrypted_data)
                        print(f"Received from client: {decrypted_msg.decode()}")
                        response = f"Message {i+1} received successfully!"
                        encrypted_response = CryptoUtils.encrypt_message(ptk, response)
                        client_socket.send(len(encrypted_response).to_bytes(4, byteorder='big'))
                        client_socket.send(encrypted_response)
                    except Exception as e:
                        print(f"Error in message exchange: {e}")
                        break                 
        finally:
            client_socket.close()
    
    def start(self):
        print(f"AP listening on {WPA3Constants.HOST}:{WPA3Constants.PORT}")
        while True:
            client_socket, client_address = self.sock.accept()
            print(f"Client connected from {client_address}")
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, client_address)
            )
            client_thread.start()
