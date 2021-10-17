import base64
import hashlib
from Crypto.Cipher import AES


class AESCipher(object):

    def __init__(self, key, iv):
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')

    def encrypt(self, raw):
        raw = raw.encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        cipher_text = cipher.encrypt(raw)
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text.decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        original_data = cipher.decrypt(enc)
        return original_data.decode('utf-8')


if __name__ == '__main__':
    aes_chipper = AESCipher("rnop3TnHwJ7P9zzLb0Z3qUjfhu1Cx9bW", "YsiebTh0Sjr8dZKo")
    enc_text = aes_chipper.encrypt('Enes')
    print(aes_chipper.decrypt(enc_text))
