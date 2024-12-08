# UTPB-COSC-6350-Project4
This repo contains the assignment for Project 4 of the graduate Wireless Security class.

The goal of this project is to simulate the WPA3 client-AP four-way handshake.

Using either Java, Python, or C#, create an implementation of the handshake a TCP server and client.  We want to properly handle every aspect of the protocol, so the amount of library use allowed is limited.

Once you have completed the simulated handshake and established a shared session key, send a few packets back and forth that are encrypted using the WPA3 standard methodology.

You may use the built-in libraries for your language of choice to handle the AES and RSA algorithms and the ECDHE exchange.  No additional library calls will be allowed.

"""
AP generates Anonce
-AP sends "message one" to client
Client receives "message one"
-derives PTK
-Already had: PMK, Snonce, client MAC
-M1 contained Anonce, AP MAC
-generates MIC using KCK
-Client sends "message two"
--contains Snonce and MIC
AP receives "message two"
-derives PTK
-generates MIC using KCK
-compares the received and derived MIC values
-AP sends "message three"
--Key install req, MIC, GTK
Client receives "message three"
-compares received MIC and derived MIC
-install PTK and GTK
-Client sends "message four"
--new MIC, ACK flag, EAPOL-Key
AP receives "message four"
-compares MIC values again
-installs PTK and GTK
PTK derivation
-requires PMK, Snonce, Anonce, CMAC, APMAC
-PMK = PBKDF2(HMAC-SHA1, PSK, SSID, 4096, 256)
--HMAC-SHA1 to encrypt data
--4096 iterations
--256-bit PMK
--SSID used as salt
--PSK used as basis
-Anonce and Snonce are random numbers
--32 bytes each (256 bits)
"""
import random
Anonce = random.getrandbits(256)
Snonce = random.getrandbits(256)
from pbkdf2 import PBKDF2
ssid = "" # AP broadcast ID
pass = "" # AP password/pairwise shared key
PMK = PBKDF2(pass, ssid, 4096).read(32).encode("hex")
import hashlib
ssid = ""
pass = ""
PMK = hashlib.pbkdf2_hmac('sha1', pass, ssid.encode(), 4096, 32)
"""
-PTK is 512 bits
-treated as five keys
-first 128 bits are KCK (key confirmation key)
-second 128 bits are KEK (key encryption key)
-third 128 bits are TK (temporal key)
-next 64 bits are MIC auth Tx key
-last 64 bits are MIC auth Rx key
"""
PKE = "Pairwise key expansion"
key_data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce)
+ max(anonce, snonce)
PTK = PRF(PMK, PKE, key_data)
KCK = PTK[:16]
KEK = PTK[16:32]
TK = PTK[32:48]
MICTx = PTK[48:56]
MICRx = PTK[56:64]
PTK = hmac.new(PMK, message, hashlib.sha1).digest()
"""
-PTK = PRF(PMK + Anonce + Snonce + AP_MAC + Client_MAC)
"""
def PRF(PMK, PKE, key_data):
numBytes = 64
i = 0
R = b''
while(i <= ((nByte * 8 + 159) // 160)):
hmacsha1 = hmac.new(key, PKE + chr(0x00).encode() + key_data +
chr(i).encode(), sha1)
R = R + hmacsha1.digest()
i += 1
return R[0:nByte]
"""
-Master Session Key (MSK)
--derived during auth (pre-handshake)
--part of 802.11 EAP protocol
-default cipher appears to be AES-CCM-128
MIC calculated for every packet
-appended to end of packet data
-MIC = HMAC_SHA1(KCK, payload)
"""
MIC = hmac.new(KCK, message, hmacFunc).digest()
#message is the complete handshake frame with the MIC field set to 0x0000
"""
Beacons (APs send out SSIDs)
Auth Request
Auth Response
Assoc Request
Assoc Response
Handshake begins
Appears to be done over TCP/IP
-ACK packets sent for every packet starting with Auth
"""
