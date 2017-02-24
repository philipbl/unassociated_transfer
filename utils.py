import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto import Random

GLOBAL_SEQUENCE_FORMAT = '!Q'
CONFIG_FILE_NAME = 'config.json'


def hash_message(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def encrypt_message(key, iv, message):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(message)


def decrypt_message(key, iv, message):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(message)


def generate_iv():
    return Random.new().read(AES.block_size)
