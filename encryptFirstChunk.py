import base64
import os
from datetime import time

from encryptVideoUsingAESandRSA import *


def read_file(path):
    with open(path, "rb") as fwrite16:
        vid_data = fwrite16.read()
    return vid_data


def chunk(action, output_file):
    video_file = output_file
    public_key_file = 'keys/pubKey/public_key.pem'
    private_key_file = 'keys/privKey/private_key.pem'

    if action == 'encrypt':
        # Encrypt the video file
        encrypted_data = encrypt_video(video_file, public_key_file)
        encrypted_aes_key, encrypted_video = encrypted_data[:-32], encrypted_data[-32:]

        # Create directories to save encrypted chunks and AES key if they don't exist
        encrypted_chunks_folder = f'content/encrypted_chunks/{os.path.splitext(os.path.basename(video_file))[0][:-4]}'
        encrypted_aes_key_folder = f'content/encrypted_aes_keys/{os.path.splitext(os.path.basename(video_file))[0][:-4]}'

        if not os.path.exists(encrypted_chunks_folder):
            os.makedirs(encrypted_chunks_folder)
        if not os.path.exists(encrypted_aes_key_folder):
            os.makedirs(encrypted_aes_key_folder)

        # Save the encrypted AES key and the encrypted video
        write_file(encrypted_aes_key,
                   os.path.join(encrypted_aes_key_folder, f'{os.path.basename(video_file)[:-4]}_encrypted_aes_key.enc'))
        write_file(encrypted_video,
                   os.path.join(encrypted_chunks_folder, f'{os.path.basename(video_file)[:-4]}_encrypted_chunk.enc'))
    elif action == 'decrypt':
        video_file = output_file
        encrypted_chunks_folder = 'content/encrypted_chunks/' + os.path.basename(video_file)[0][:-7]
        encrypted_aes_key_folder = 'content/encrypted_aes_keys/' + os.path.basename(video_file)[0][:-7]

        # Read the encrypted AES key and the encrypted video
        encrypted_aes_key_filename = f'{os.path.splitext(os.path.basename(video_file))[0]}_encrypted_aes_key.enc'
        encrypted_video_filename = f'{os.path.splitext(os.path.basename(video_file))[0]}_encrypted_chunk.enc'
        encrypted_aes_key = read_file(os.path.join(encrypted_aes_key_folder, encrypted_aes_key_filename))
        encrypted_video = read_file(os.path.join(encrypted_chunks_folder, encrypted_video_filename))

        # Decrypt the encrypted video using the encrypted AES key
        decrypted_video = decrypt_video(encrypted_aes_key + encrypted_video, private_key_file)

        # Save the decrypted video
        decrypted_folder = 'content/decrypted_chunks/' + os.path.basename(video_file)[0]
        if not os.path.exists(decrypted_folder):
            os.makedirs(decrypted_folder)

        write_file(decrypted_video,
                   os.path.join(decrypted_folder, f'{os.path.basename(video_file)[0]}_decrypted_chunk.mp4'))


def save_nonce(nonce):
    nonce_base64 = base64.b64encode(nonce)
    with open('content/Nonce_Tag_data/nonce.txt', 'w') as file:
        file.write(nonce_base64.decode('utf-8'))


def save_tag(tag):
    tag_base64 = base64.b64encode(tag)
    with open('content/Nonce_Tag_data/tag.txt', 'w') as file:
        file.write(tag_base64.decode('utf-8'))


def read_nonce():
    with open('content/Nonce_Tag_data/nonce.txt', 'r') as file:
        nonce_base64 = file.read()
        nonce = base64.b64decode(nonce_base64)
        print("type of nonce after reading during decryption", type(nonce))
    return nonce


def read_tag():
    with open('content/Nonce_Tag_data/tag.txt', 'r') as file:
        tag_base64 = file.read()
        tag = base64.b64decode(tag_base64)
        print("type of tah after reading during decryption", type(tag))
    return tag
