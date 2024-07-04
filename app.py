from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

app = Flask(__name__)

# Encryption key and salt should be securely stored and managed
PASSWORD = b'my_secret_password'
SALT = os.urandom(16)

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt(plain_text: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return urlsafe_b64encode(iv + encrypted).decode('utf-8')

def decrypt(encrypted_text: str, key: bytes) -> str:
    data = urlsafe_b64decode(encrypted_text)
    iv = data[:16]
    encrypted = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return decrypted.decode('utf-8')

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.get_json()
    plain_text = data['text']
    key = derive_key(PASSWORD, SALT)
    encrypted_text = encrypt(plain_text, key)
    return jsonify({'encrypted': encrypted_text})

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    data = request.get_json()
    encrypted_text = data['text']
    key = derive_key(PASSWORD, SALT)
    decrypted_text = decrypt(encrypted_text, key)
    return jsonify({'decrypted': decrypted_text})

if __name__ == '__main__':
    app.run(debug=True)
