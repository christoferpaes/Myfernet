import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class MyFernet:
    def __init__(self, password):
        # Derive a key from the password
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Set up the encryption and decryption cipher
        self.cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(b'initialization_vector')
        )

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext

    def decrypt(self, ciphertext):
        decryptor = self.cipher.decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()
        return data
