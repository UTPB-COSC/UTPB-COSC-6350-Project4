# Gabriel Kyle Manalastas
# 8000232781 
# manalastas_g32781@utpb.edu
# Better late than never, and something over nothing. 

import random
import socket
import hashlib
import threading
import time


# Basic RSA 
def extendedGCD(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extendedGCD(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def modInverse(a, m):
    g, x, y = extendedGCD(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generateRSAKeys(bits=8):
    p = generatePrime(bits)
    q = generatePrime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537  
    while extendedGCD(e, phi_n)[0] != 1:
        e = random.randint(2, phi_n - 1)

    d = modInverse(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def checkPrime(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generatePrime(bits=8):
    while True:
        num = random.randint(2**(bits-1), 2**bits)
        if checkPrime(num):
            return num

def rsaEncrypt(public_key, plaintext):
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext

def rsaDecrypt(private_key, ciphertext):
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext

def xorBytes(byte_data, key):
    return [b ^ key for b in byte_data]

def simplifyAesEncrypt(session_key, plaintext):
    rounds = 5
    byte_data = [ord(c) for c in plaintext]

    byte_data = xorBytes(byte_data, session_key)

    for _ in range(rounds):
        byte_data = xorBytes(byte_data, session_key)
        byte_data = byte_data[1:] + byte_data[:1]  

    return byte_data

def simplifyAesDecrypt(session_key, encrypted_data):
    rounds = 5
    byte_data = encrypted_data

    for _ in range(rounds):
        byte_data = byte_data[-1:] + byte_data[:-1]  
        byte_data = xorBytes(byte_data, session_key)

    byte_data = xorBytes(byte_data, session_key)

    return ''.join(chr(b) for b in byte_data)

class ECDHE:
    def __init__(self, p, g):
        self.p = p  
        self.g = g  
        self.private_key = random.randint(2, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return shared_secret


def client():
    try:
        host = '127.0.0.1'  
        port = 5201  

        p = 23             
        g = 5     

        ecdhe = ECDHE(p, g)
        public_rsa, private_rsa = generateRSAKeys(bits=8)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))

            ap_public_key = int(client_socket.recv(1024).decode())
            print(f"[Client] received AP public key: {ap_public_key}")

            client_socket.sendall(str(ecdhe.public_key).encode())
            print(f"[Client] public key sent: {ecdhe.public_key}")
    
            client_socket.sendall(str(public_rsa).encode())  
            print(f"[Client] sent RSA public key")

            ap_public_rsa = client_socket.recv(1024)
            print(f"[Client] received AP's RSA public key: {ap_public_rsa.decode()}")

            shared_secret = ecdhe.compute_shared_secret(ap_public_key)
            print(f"[Client] shared secret: {shared_secret}")
            session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()  
            print(f"[Client] session key established: {session_key}")

            for _ in range(3):
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:  
                    print("Nothing received. Connection might be closed.")
                    break

                decrypted_msg = simplifyAesDecrypt(int(session_key[:4], 16), list(encrypted_message))
                print(f"[Client] decrypted: {decrypted_msg}")
                time.sleep(2)

        print("[Client] task finished!")
    except Exception as e:
        print(f"Error in client: {e}")

def ap_server():
    try:
        host = '127.0.0.1'  
        port = 5201    

        p = 23              
        g = 5     

        ecdhe = ECDHE(p, g)
        public_rsa, private_rsa = generateRSAKeys(bits=8)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
            server_socket.bind((host, port))
            server_socket.listen()
            print("Server waiting for connection...")

            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")

                conn.sendall(str(ecdhe.public_key).encode())
                print(f"[AP] public key sent: {ecdhe.public_key}")

                client_public_key = int(conn.recv(1024).decode())
                print(f"[AP] received client public key: {client_public_key}")

                client_rsa_public_key = conn.recv(1024).decode() 
                print(f"[AP] received client RSA public key: {client_rsa_public_key}")
                conn.sendall(str(public_rsa).encode())  
                print(f"[AP] sent RSA public key")

                shared_secret = ecdhe.compute_shared_secret(client_public_key)
                print(f"[AP] shared secret: {shared_secret}")
                session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()  
                print(f"[AP] session key established: {session_key}")

                messages = ["[PACKET 1]", "[PACKET 2]", "[FINAL PACKET]"]
                for message in messages:
                    encrypted_msg = simplifyAesEncrypt(int(session_key[:4], 16), message)
                    conn.sendall(bytes(encrypted_msg))
                    print(f"[AP] encrypted message sent: {encrypted_msg}")
                    time.sleep(1)  

            print("Server task finished!")
    except Exception as e:
        print(f"Error in ap_server: {e}")

if __name__ == "__main__":
    server_thread = threading.Thread(target=ap_server)
    server_thread.start()

    client()

    server_thread.join()  
    print("Main program complete.")