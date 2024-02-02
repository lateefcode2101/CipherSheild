from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import padding

# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()


def ecc_encrypt(plaintext, public_key):
    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Generate shared secret
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive key from shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES key length
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    # Generate random IV
    iv = os.urandom(16)

    # Encrypt plaintext using AES-CBC with PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return public_key_bytes, iv, ciphertext


def ecc_decrypt(public_key_bytes, iv, ciphertext, private_key):
    # Deserialize public key
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    # Generate shared secret
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive key from shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES key length
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    # Decrypt ciphertext using AES-CBC
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_message) + unpadder.finalize()

    return plaintext


# Encrypt message
public_key_bytes, iv, ciphertext = ecc_encrypt("BIsmillah".encode(), public_key)
print("Encrypted:", ciphertext)

# Decrypt message
decrypted_message = ecc_decrypt(public_key_bytes, iv, ciphertext, private_key)
print("Decrypted:", decrypted_message)
print("iv is ", iv)
