import hmac
from Crypto.Cipher import AES

def hash_message(key, message):
    return hmac.new(key, message).digest()


def encrypt_message(key, message):
    aes = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    return aes.encrypt(message)


def decrypt_message(key, message):
    aes = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    return aes.decrypt(message)
