from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# The encrypted data (output from the encryption process)
ciphertext = b'\x06\x12M\x90x$\xd0\xd4\x16\xb1\x06_\xb1\xc7\xdc\xbd\x10x\xa7\xe6\x9a\xe1>\x94&c\xf2\xe1\x9f\x8f\x14\xde'  # The encrypted message in bytes
nonce = b'\\3e\x7f\xc1\xa27<\xd1\x1d]\xd6'  # The nonce used in the encryption process
tag = b'-}\x96\x1f\x1ff\xc3&\x1a\xca\xe7\xe4\xa7U{\x1a'  # The authentication tag from the encryption process

# The AES key (used in the encryption process)
aes_key = b'\x04\xb6\xe6\xbaJ0\x90\xa9\x8e\\\xd2^\xc6\xc9\x8dfq1M\xce\x04\xba]-\x0cl\xf8/\xa6J\x81\xb1'  # 32 bytes for AES-256

# The additional data to authenticate (same as in the encryption process)
additional_data = b"Authenticated Data"

# Create a Cipher object using the AES key and GCM mode
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())

# Create a decryptor
decryptor = cipher.decryptor()

# Authenticate the additional data
decryptor.authenticate_additional_data(additional_data)

# Decrypt the ciphertext
decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Print the decrypted plaintext
print(f"Decrypted Plaintext: {decrypted_plaintext.decode()}")
