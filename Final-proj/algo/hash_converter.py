import base64
import os
import hashlib
import codecs
from flask import Blueprint, render_template, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from middleware.detect_xss import detect_xss


routes = Blueprint('routes', __name__)
SECRET_KEY = b'Sixteen byte key'  # Replace with secure 32-byte key

# AES functions
def encrypt_aes(message, key):
    # Ensure the key is 16, 24, or 32 bytes long (AES requirement)
    key = hashlib.sha256(key.encode()).digest()  # Normalize key to 32 bytes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_aes(ciphertext, key):
    try:
        key = hashlib.sha256(key.encode()).digest()  # Normalize key
        raw = base64.b64decode(ciphertext)
        iv = raw[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(raw[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted = unpadder.update(padded) + unpadder.finalize()
        return decrypted.decode()
    except Exception as e:
        return f"Decryption failed! {str(e)}"

# Base64
def encrypt_base64(message):
    return base64.b64encode(message.encode()).decode()

def decrypt_base64(ciphertext):
    try:
        return base64.b64decode(ciphertext).decode()
    except Exception:
        return "Invalid Base64 input."

# ROT13
def encrypt_rot13(message):
    return codecs.encode(message, 'rot_13')

def decrypt_rot13(message):
    return codecs.decode(message, 'rot_13')

# Hash functions (one-way)
def hash_md5(message):
    return hashlib.md5(message.encode()).hexdigest()

def hash_sha1(message):
    return hashlib.sha1(message.encode()).hexdigest()

def hash_sha256(message):
    return hashlib.sha256(message.encode()).hexdigest()

@routes.route('/hash_converter', methods=['GET', 'POST'])
def hash_converter():
    encrypted_text = decrypted_text = None
    if request.method == 'POST':
        text = request.form['text']
        action = request.form['action']
        method = request.form['method']

        if action == 'encrypt':
            if method == 'aes':
                encrypted_text = encrypt_aes(text)
            elif method == 'base64':
                encrypted_text = encrypt_base64(text)
            elif method == 'rot13':
                encrypted_text = encrypt_rot13(text)
            elif method == 'md5':
                encrypted_text = hash_md5(text)
            elif method == 'sha1':
                encrypted_text = hash_sha1(text)
            elif method == 'sha256':
                encrypted_text = hash_sha256(text)
        elif action == 'decrypt':
            if method == 'aes':
                decrypted_text = decrypt_aes(text)
            elif method == 'base64':
                decrypted_text = decrypt_base64(text)
            elif method == 'rot13':
                decrypted_text = decrypt_rot13(text)

    return render_template('hash_converter.html', encrypted_text=encrypted_text, decrypted_text=decrypted_text)
