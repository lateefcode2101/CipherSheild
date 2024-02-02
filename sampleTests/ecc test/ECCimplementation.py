import uuid
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def get_vid():
    with open('VID.txt', "rb") as fwrite16:
        vid_data = fwrite16.read()
    return vid_data


def get_mac_address():
    mac = uuid.getnode()
    return ''.join(("%012X" % mac)[i:i + 2] for i in range(0, 12, 2))


# Define the elliptic curve parameters
curve = ec.SECP256R1()

# Generate a key pair for ECDSA
private_key = ec.generate_private_key(curve, default_backend())
public_key = private_key.public_key()


def derive_key(vid, mac_address):
    vid_int = int.from_bytes(vid, byteorder='big')
    mac_int = int.from_bytes(mac_address.encode(), byteorder='big')

    x = vid_int ^ mac_int
    key_a = x ** 3 + vid_int * x + mac_int

    key_a_bytes = key_a.to_bytes((key_a.bit_length() + 7) // 8, byteorder='big')

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ECC key derivation',
        backend=default_backend()
    )
    key = hkdf.derive(key_a_bytes)

    return key


def generate_key(vid, mac_address):
    key = derive_key(vid, mac_address)
    return key


def encrypt_data(data, key):
    # Load the public key from the provided byte string
    peer_public_key = serialization.load_der_public_key(key, backend=default_backend())

    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Use HKDF for key derivation from shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ECIES key derivation',
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_key)

    # Encrypt the data using the derived key
    ciphertext = derived_key + data

    return ciphertext


def decrypt_data(ciphertext, key):
    # Load the private key from the provided byte string
    private_key = serialization.load_der_private_key(key, password=None, backend=default_backend())

    # Perform ECDH key exchange
    shared_key = private_key.exchange(ec.ECDH())

    # Use HKDF for key derivation from shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ECIES key derivation',
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_key)

    # Decrypt the data using the derived key
    decrypted_data = ciphertext[len(derived_key):]

    return decrypted_data


# Usage example:
vid = get_vid()
mac_address = get_mac_address()

key = generate_key(vid, mac_address)

plaintext = b'Some secret data to encrypt'
encrypted_data = encrypt_data(plaintext, key)
decrypted_data = decrypt_data(encrypted_data, key)

print("Original data:", plaintext)
print("Encrypted data:", encrypted_data)
print("Decrypted data:", decrypted_data)
