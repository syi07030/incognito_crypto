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
    pwd = os.getcwd()
    print(pwd)
##########################
    #file = open("sample.bin", "wb")
    #file.write(b"\x88\xae\x97B\x94\xcf\x95\xe8\x98\x8bS\xf8\xf1\xb3\xcajl\xb9\xe7\xba\xda\xc57 AP\x18z\xf5E\xda1")
    #file.close 
############################
    flag = open(pwd+'\Desktop\incognito_crypto\sample.bin', 'rb').read().strip()
    print(flag)
    '''#flag = binascii.unhexlify("494e434f7b643363727970745f7375636365357321217d")
    print(len(flag)) #23-byte
    xore = XOR()
    xore_flag = xore.encrypt(flag)
    aese = AES256()
    encrypt_flag = aese.encrypt(xore_flag)'''

    #fw = open('output.txt', 'w')
    #fw.write("encrypt flag: ", encrypt_flag)
    #fw.close()
    print(">>>>>encrypt flag: ", flag)

    xord = XOR()
    aesd = AES256()
    decrypt_flag = aesd.decrypt(flag)
    print("only aes decrypt: ", decrypt_flag)
    print(binascii.b2a_hex(decrypt_flag))
    xord_flag = xord.decrypt(decrypt_flag)
    print ('>>>>>decrypt flag:', xord_flag)

if __name__ == '__main__':
    main()

    #encrypt flag값을 아예 텍스트 파일로 저장해서 문제랑 함께 주고 -> 아니면 그냥 코드에 박아버리기
    #사람들이 decrypt 부분 함수를 채워서 그 파일을 열어서 복호화를 성공적으로 하면 플래그 값 획득
    #aes 키 값은 그냥 코드에서 주는 거 확정, xor같은 경우도 그냥 키 값 주어지는 건 어떨지