import os
import binascii
from Crypto.Cipher import AES
import hashlib

class XOR:
    def __init__(self):
        #self.key = os.urandom(5)
        self.key = binascii.unhexlify("132b37c5f8")
    def encrypt(self, data: bytes) -> bytes:
        xored = b''
        for i in range(len(data)):
            xored += bytes([data[i] ^ self.key[i % len(self.key)]])
        return xored
    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

class AES256:
    def __init__(self):
        #self.key = hashlib.sha256(key).digest
        iv = b'\x00'*16
        self.key = b'12345678901234567890123456789012'
        self.crypto = AES.new(self.key, AES.MODE_CBC, iv)
    def encrypt(self, msg):
        msg = msg + b'\x00'*(32-len(msg))
        #msg.ljust(32,0)
        cipher = self.crypto.encrypt(msg)
        return cipher
    def decrypt(self, enc):
        msg = self.crypto.decrypt(enc)
        return msg[:23]

def main():
    #flag = open('flag.txt', 'r').read().strip().encode()
    flag = binascii.unhexlify("494e434f7b643363727970745f7375636365357321217d")
    print(len(flag)) #23-byte
    xore = XOR()
    xore_flag = xore.encrypt(flag)
    print(type(xore_flag))
    aese = AES256()
    encrypt_flag = aese.encrypt(xore_flag)
    #fw = open('output.txt', 'w')
    #fw.write("encrypt flag: ", encrypt_flag)
    #fw.close()
    print(">>>>>encrypt flag: ", encrypt_flag)

    xord = XOR()
    aesd = AES256()
    decrypt_flag = aesd.decrypt(encrypt_flag)
    xord_flag = xord.decrypt(decrypt_flag)
    print ('>>>>>decrypt flag:', xord_flag)

if __name__ == '__main__':
    main()