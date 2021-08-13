import os
import binascii
from Crypto.Cipher import AES

class XOR:
    def __init__(self):
        self.key = os.urandom(5)
        #print("key = ", binascii.b2a_hex(self.key))
        self.key = binascii.unhexlify("132b37c5f8")
        #print("length of key = ", len(self.key))
    def encrypt(self, data: bytes) -> bytes:
        enc = b''
        for i in range(len(data)):
            enc += bytes([data[i] ^ self.key[i % 5]])
        return enc
    def decrypt(self, data: bytes) -> bytes:
        #complete this method
        return self.encrypt(data)

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
        #flag length is 23-byte
        msg = self.crypto.decrypt(enc)
        return msg[:23]

def main():
    pwd = os.getcwd()
    flag = open(pwd+'/desktop/hgy/INCOGNITO/ctf/flag.bin', 'rb').read().strip()
    #print(flag)
    #flag = binascii.unhexlify("494e434f7b643363727970745f7375636365357321217d")
    #print(len(flag)) #23-byte
    #xore = XOR()
    #xore_flag = xore.encrypt(flag)
    #aese = AES256()
    #encrypt_flag = aese.encrypt(xore_flag)
    
    #fw = open('output.txt', 'w')
    #fw.write("encrypt flag: ", encrypt_flag)
    #fw.close()
    print(">>>>>encrypt flag: ", flag)

    xord = XOR()
    aesd = AES256()
    decrypt_flag = aesd.decrypt(flag)
    #print("only aes decrypt: ", decrypt_flag)
    print("only aes decrypt: ", binascii.b2a_hex(decrypt_flag))
    xord_flag = xord.decrypt(decrypt_flag)
    print ('>>>>>decrypt flag:', xord_flag)

if __name__ == '__main__':
    main()