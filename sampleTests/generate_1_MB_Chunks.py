import base64
import os
import subprocess
import re

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_key():
    return Fernet.generate_key()


# Function to generate a key for asymmetric encryption (RSA)
def generate_asymmetric_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def get_video_duration(input_file):
    result = subprocess.run([
        'E:\\installs\\ffmpeg\\bin\\ffprobe.exe',
        '-i', input_file,
        '-show_entries', 'format=duration',
        '-v', 'quiet',
        '-of', 'csv=p=0'
    ], capture_output=True, text=True)

    return float(result.stdout.strip())


def split_video_ffmpeg(input_file, output_folder, target_chunk_size_MB):
    # Check if the output folder exists, create it if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get the total size of the input video file
    total_size = os.path.getsize(input_file)

    # Define the target chunk size in bytes
    target_chunk_size_bytes = target_chunk_size_MB * 1024 * 1024  # Convert MB to bytes

    # Calculate the number of chunks needed
    num_chunks = total_size // target_chunk_size_bytes + (total_size % target_chunk_size_bytes > 0)

    # Get video duration using ffprobe
    duration = get_video_duration(input_file)

    # Generate encryption key
    encryption_key = generate_key()

    # Generate RSA key pair for asymmetric encryption
    private_key, public_key = generate_asymmetric_key()

    # Use FFmpeg to split the video into consecutive chunks of 1MB each
    for i in range(num_chunks):
        output_file = os.path.join(output_folder, f'part_{i + 1}.mp4')
        output_metadata_file = os.path.join(output_folder, f'metadata.txt')
        output_encrypted_file = os.path.join(output_folder, f'part_{i + 1}.enc')

        # Calcul ate the start position for the current chunk
        start_position = i * target_chunk_size_bytes

        # Run FFmpeg command to create the chunk based on the start position and size
        start_position_seconds = start_position / total_size * duration
        subprocess.run([
            'E:\\installs\\ffmpeg\\bin\\ffmpeg.exe',
            '-i', input_file,
            '-c', 'copy',
            '-map', '0',
            '-ss', f'{start_position_seconds:.6f}',  # Format the start position as ss.mmm
            '-fs', f'{target_chunk_size_bytes}',
            output_file
        ], check=True)

        encrypt_file(output_file, output_encrypted_file, encryption_key)

        # Encrypt the chunk with symmetric key (Fernet)
        output_encrypted_file = encrypt_file_with_symmetric_key(encryption_key, output_encrypted_file)

        # Encrypt the chunk with RSA public key, using previous output as key
        output_encrypted_file = encrypt_file_with_rsa(public_key, output_encrypted_file)

        # Assuming you have the public key in a file named 'public_key.pem'
        with open('public_key.pem', 'rb') as public_key_file:
            public_key_content = public_key_file.read()

        # Encode the public key content in base64 for inclusion in metadata
        public_key_base64 = base64.b64encode(public_key_content).decode('utf-8')

        # Use the actual MAC address
        mac_address = '\n88-B1-11-8A-B9-E3'

        # Construct metadata using the base64-encoded public key and MAC address
        metadata = f'RPkey:{public_key_base64},Rmac:{mac_address}'

        with open(output_metadata_file, 'wb') as file:
            file.write(metadata.encode())


# Function to encrypt a file
def encrypt_file(input_file, output_file, key):
    cipher = Fernet(key)

    with open(input_file, 'rb') as file:
        data = file.read()

    encrypted_data = cipher.encrypt(data)

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)


# Function to encrypt a file with RSA public key
def encrypt_file_with_rsa(public_key, input_file):
    with open(input_file, 'rb') as file:
        data = file.read()

    # Encrypt the data in chunks to handle large files
    encrypted_data = b""
    chunk_size = 128  # Adjust this based on key size

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_data += encrypted_chunk

    with open(input_file, 'wb') as file:
        file.write(encrypted_data)


# Function to decrypt a file with RSA private key
def decrypt_file_with_rsa(private_key, input_file, output_file):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)


# Function to encrypt a file with symmetric key (Fernet)
def encrypt_file_with_symmetric_key(sym_key, input_file):
    cipher = Fernet(sym_key)

    with open(input_file, 'rb') as file:
        data = file.read()

    encrypted_data = cipher.encrypt(data)

    with open(input_file, 'wb') as file:
        file.write(encrypted_data)

    return input_file


# Function to decrypt a file with symmetric key (Fernet)
def decrypt_file_with_symmetric_key(sym_key, input_file, output_file):
    cipher = Fernet(sym_key)

    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)


if __name__ == "__main__":
    video_path = 'Original_chunking_Video.mp4'  # Replace with the path to your video file
    target_chunk_size_MB = 1  # Specify the target size of each chunk in megabytes

    split_video_ffmpeg(video_path, ''.join(["chunks_of_", video_path])[:-4], target_chunk_size_MB)
