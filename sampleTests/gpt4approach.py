import os
import base64
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from time import time


def generate_vid(chunk):
    return base64.b64encode(chunk[:16]).decode('utf-8')


def ecc_key_generation(x, vid_or_key, mac):
    return x ** 3 + vid_or_key * x + mac


def encrypt_rsa(public_key, data):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)


def decrypt_rsa(private_key, data):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(data)


def encrypt_aes(key, data):
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return cipher_aes.nonce, ciphertext, tag


def decrypt_aes(key, nonce, ciphertext, tag):
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data


def main():
    # Example video file
    video_file = 'example_video.mp4'

    # Generate RSA keys
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    # Simulate MAC address
    mac_address = int(hashlib.sha256(b'receiver_mac').hexdigest(), 16) % (10 ** 8)

    # Read video file
    with open(video_file, 'rb') as f:
        video_data = f.read()

    # Split video into chunks
    chunk_size = 1024 * 1024  # 1 MB
    chunks = [video_data[i:i + chunk_size] for i in range(0, len(video_data), chunk_size)]

    # Encrypt chunks
    encrypted_chunks = []
    vid = generate_vid(chunks[0])
    start_time = time()

    # Encrypt first chunk using RSA
    encrypted_chunks.append(encrypt_rsa(RSA.import_key(public_key), chunks[0]))

    # Encrypt subsequent chunks using AES with dynamic keys
    key_a = ecc_key_generation(3, int.from_bytes(vid.encode(), 'big'), mac_address)
    for i in range(1, len(chunks)):
        key = hashlib.sha256(str(key_a).encode()).digest()
        nonce, ciphertext, tag = encrypt_aes(key, chunks[i])
        encrypted_chunks.append((nonce, ciphertext, tag))
        key_a = ecc_key_generation(3, key_a, mac_address)

    encryption_time = time() - start_time
    print(f'Encryption Time: {encryption_time:.2f} seconds')

    # Decrypt chunks
    decrypted_chunks = []
    start_time = time()

    # Decrypt first chunk using RSA
    decrypted_chunks.append(decrypt_rsa(RSA.import_key(private_key), encrypted_chunks[0]))

    # Decrypt subsequent chunks using AES with dynamic keys
    key_a = ecc_key_generation(3, int.from_bytes(vid.encode(), 'big'), mac_address)
    for i in range(1, len(encrypted_chunks)):
        key = hashlib.sha256(str(key_a).encode()).digest()
        nonce, ciphertext, tag = encrypted_chunks[i]
        decrypted_chunks.append(decrypt_aes(key, nonce, ciphertext, tag))
        key_a = ecc_key_generation(3, key_a, mac_address)

    decryption_time = time() - start_time
    print(f'Decryption Time: {decryption_time:.2f seconds}')

    # Combine decrypted chunks
    decrypted_video_data = b''.join(decrypted_chunks)

    # Save decrypted video
    with open('decrypted_video.mp4', 'wb') as f:
        f.write(decrypted_video_data)

    print('Decryption complete, video saved as decrypted_video.mp4')


if __name__ == '__main__':
    main()
