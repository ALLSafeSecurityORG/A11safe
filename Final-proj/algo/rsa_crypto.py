from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def rsa_encrypt(plaintext, public_key_str):
    public_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(ciphertext_b64, private_key_str):
    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext_b64))
    return decrypted.decode()
