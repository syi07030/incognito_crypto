import os
import binascii
from Crypto.Cipher import AES

class XOR:
    def __init__(self):
        self.key = os.urandom(5) #find key value
    def encrypt(self, data: bytes) -> bytes:
        enc = b''
        for i in range(len(data)):
            enc += bytes([data[i] ^ self.key[i % 5]])
        return enc
    def decrypt(self, data: bytes) -> bytes:
        #complete this method
        return

class AES256:
    def __init__(self):
        iv = b'\x00'*16
        self.key = b'12345678901234567890123456789012'
        self.crypto = AES.new(self.key, AES.MODE_CBC, iv)
    def encrypt(self, msg):
        msg = msg + b'\x00'*(32-len(msg))
        cipher = self.crypto.encrypt(msg)
        return cipher
    def decrypt(self, enc): 
        #complete this method
        #final flag length is 23-byte
        return

def main():
    flag = open('flag.bin', 'rb').read().strip()
    print(">>>>>encrypt flag: ", flag)

    xord = XOR()
    aesd = AES256()
    decrypt_flag = aesd.decrypt(flag)
    print("only aes decrypt: ", binascii.b2a_hex(decrypt_flag))
    xord_flag = xord.decrypt(decrypt_flag)
    print ('>>>>>decrypt flag:', xord_flag)

if __name__ == '__main__':
    main()
