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
    def __init__(self, key):
        #self.key = hashlib.sha256(key).digest
        iv = chr(0)*16
        #self.key = chr(1)*32
        #bs = AES.block_size
        self.crypto = AES.new(key, AES.MODE_CBC, iv)
    def encrypt(self, msg):
        msg = msg + "0"*(32-len(msg))
        #msg.ljust(32,0)
        cipher = self.crypto.encrypt(msg)
        return cipher
    def decrypt(self, enc):
        enc = enc[:184]
        msg = self.crypto.decrypt(enc)
        return msg

def main():
    #flag = open('flag.txt', 'r').read().strip().encode()
    flag = binascii.unhexlify("494e434f7b643363727970745f7375636365357321217d")
    print(len(flag)) #23-byte
    xor = XOR()
    xore_flag = xor.encrypt(flag)
    print(type(xore_flag))
    aes = AES256([0x10,0x01]*16)
    encrypt_flag = aes.encrypt(xore_flag)
    #fw = open('output.txt', 'w')
    #fw.write("encrypt flag: ", encrypt_flag)
    #fw.close()
    print("encrypt flag: ", encrypt_flag)
    xord_flag = xor.decrypt()
    decrypt_flag = aes.decrypt(xord_flag)
    print ('decrypt flag:', xor.decrypt(decrypt_flag))

if __name__ == '__main__':
    main()

#따로 텍스트 주지 말고 실행했을 때 나오는 output -> 텍스트 파일로 저장
#문제는 플래그 값 암호화된 거를 어떻게 저장할지
#padding?
