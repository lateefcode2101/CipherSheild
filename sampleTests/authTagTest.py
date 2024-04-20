from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

# Generate a random AES key
import os

aes_key = os.urandom(32)  # 32 bytes for AES-256
print(aes_key)
# Generate a nonce for AES-GCM (typically 12 bytes)
nonce = os.urandom(12)

# The additional data to authenticate (convert the string to bytes)
additional_data = b"Authenticated Data"

# The plaintext to encrypt
plaintext = b"Hello, this is a secret message."

# Create a Cipher object using the AES key and GCM mode
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())

# Create an encryptor
encryptor = cipher.encryptor()

# Authenticate the additional data
encryptor.authenticate_additional_data(additional_data)

# Encrypt the plaintext
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Retrieve the authentication tag
tag = encryptor.tag

# Print the results
print(f"Ciphertext: {ciphertext}")
print(f"Nonce: {nonce}")
print(f"Authentication Tag: {tag}")

# The `ciphertext`, `nonce`, and `tag` values will be required for decryption later
