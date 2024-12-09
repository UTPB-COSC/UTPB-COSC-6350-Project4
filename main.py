import threading
from WPA3Client import WPA3Client
from WPA3AP import WPA3AP
import time

def run_ap():
    ap = WPA3AP()
    ap.start()

def run_client():
    client = WPA3Client()
    client.connect()

if __name__ == "__main__":
    ap_thread = threading.Thread(target=run_ap)
    ap_thread.start()
    time.sleep(1)
    client_thread = threading.Thread(target=run_client)
    client_thread.start()
    ap_thread.join()
    client_thread.join()