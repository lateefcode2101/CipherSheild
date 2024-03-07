# Function to generate a random AES key
def generate_aes_key():
    with open('keys/aesKey/aes_key.txt', 'rb') as file:
        aes_key = file.read().strip()
        print("type of aes key read is ", type(aes_key))
    return aes_key  # AES key size is 16 bytes (128 bits)


# Function to read the video file
def read_video_file(file_path):
    with open(file_path, 'rb') as f:
        fileData = f.read()
    return fileData


# Function to write data to a file
def write_file(data, file_path):
    with open(file_path, 'wb') as f:
        f.write(data)


# Function to encrypt data using AES
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag


# Function to decrypt data using AES
def aes_decrypt(ciphertext, key, nonce, tag):
    nonce_bytes = nonce  # .encode('utf-8') if isinstance(nonce, str) else nonce # Convert nonce string to bytes
    # using UTF-8 encoding
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
    tag_bytes = tag  # .encode('utf-8') if isinstance(tag, str) else tag
    plaintext = cipher.decrypt_and_verify(ciphertext, tag_bytes)
    return plaintext


# Function to encrypt the video file using RSA for the AES key
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt_video(video_file, public_key_file):
    # Read the video file
    video_data = read_video_file(video_file)

    # Generate a random AES key
    aes_key = generate_aes_key()

    # Encrypt the video data using AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    encrypted_video, tag = cipher_aes.encrypt_and_digest(video_data)
    nonce = cipher_aes.nonce

    # Read the public key
    with open(public_key_file, 'rb') as f:
        public_key = RSA.import_key(f.read())

    # Initialize the cipher with the public key
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Encrypt the AES key using RSA
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    print("size of encrypted_aes_key", len(encrypted_aes_key))
    print("size of encrypted_video", len(encrypted_video))
    # Combine encrypted AES key, nonce, tag, and encrypted video data
    encrypted_data = encrypted_aes_key + nonce + tag + encrypted_video

    return encrypted_data


# Function to decrypt the video file using RSA for the AES key
def decrypt_video(encrypted_data, private_key_file):
    # Read the private key
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())

    # Initialize the cipher with the private key
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Extract the encrypted AES key, nonce, tag, and encrypted video data
    aes_key_size = 256  # Assuming AES key size of 256 bits
    encrypted_aes_key = encrypted_data[:aes_key_size]
    nonce = encrypted_data[aes_key_size:aes_key_size + 16]  # Nonce size for AES GCM mode is typically 16 bytes
    tag_start = aes_key_size + 16
    tag_end = tag_start + 16  # Tag size for AES GCM mode is typically 16 bytes
    tag = encrypted_data[tag_start:tag_end]
    encrypted_video = encrypted_data[tag_end:]

    # Decrypt the AES key using RSA
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Initialize the AES cipher with the decrypted AES key, nonce, and tag
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_video = cipher_aes.decrypt_and_verify(encrypted_video, tag)

    return decrypted_video
