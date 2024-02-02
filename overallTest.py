import base64
import math
import os
import shutil
import subprocess
import time

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# from encryptVideoUsingAESandRSA import encrypt_video, decrypt_video, write_file, generate_aes_key
from ClearFolders import delete_files_in_subfolders


# from encryptFirstChunk import chunk
# from encryptVideoUsingAESandRSA import encrypt_video, decrypt_video

def read_video_file(file_path):
    with open(file_path, 'rb') as f:
        fileData = f.read()
    return fileData


def generate_aes_key():
    with open('keys/aesKey/aes_key.txt', 'rb') as file:
        aes_key = file.read().strip()
        print("type of aes key read is ", type(aes_key))
    return aes_key  # AES key size is 16 bytes (128 bits)


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


def write_file(data, file_path):
    with open(file_path, 'wb') as f:
        f.write(data)


# Function to read data from a file
def read_file(path):
    with open(path, "rb") as file:
        data = file.read()
    return data


# Function to split the video using FFmpeg
def split_video_ffmpeg(input_file, output_folder, target_chunk_size_MB_param, segment_duration):
    # Check if the output folder exists, create it if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get video duration using ffprobe
    duration = get_video_duration(input_file)

    # Check if the output folder exists, create it if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get the total size of the input video file
    total_size = os.path.getsize(input_file)

    # Define the target chunk size in bytes
    target_chunk_size_bytes = 1 * 1024 * 1024  # Convert MB to bytes

    # Calculate the number of chunks needed
    num_chunks = total_size // target_chunk_size_bytes + (total_size % target_chunk_size_bytes > 0)

    # Get video duration using ffprobe
    duration = get_video_duration(input_file)

    # Use FFmpeg to split the video into consecutive chunks of 1MB each
    for i in range(num_chunks):
        output_file = os.path.join(output_folder, f'part_{i + 1}.mp4')

        # Calculate the start position for the current chunk
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


# Function to save the first video chunk bytes
def save_first_video_chunk_bytes(i, output_file, action):
    with open(output_file, 'rb') as f:
        chunk_data = f.read()
        print("Chunk data read is of size ", len(chunk_data))
        with open(f'content/ChunkData/{i + 1}_chunk_bytes.txt', "wb") as fwrite:
            fwrite.write(chunk_data)
        start_time = time.time()
        chunk('encrypt', output_file)
        end_time = time.time()  # Record the end time
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.6f} seconds")

        # Find the position of the first occurrence of "!"
        bmdat_position = chunk_data.find(b'!')

        # Ensure "!" is found before attempting to extract bytes
        if bmdat_position != -1:
            # Extract the 16 bytes after the occurrence of "!"
            extracted_bytes = chunk_data[bmdat_position + len('!'): bmdat_position + len('!') + 16]
            extracted_bytes_base64 = base64.b64encode(extracted_bytes).rstrip(b'=')
            with open('content/Vid/VID.txt', "wb") as fwrite_base64:
                fwrite_base64.write(extracted_bytes_base64)


# Function to get the video duration using ffprobe
def get_video_duration(input_file):
    result = subprocess.run([
        'E:\\installs\\ffmpeg\\bin\\ffprobe.exe',
        '-i', input_file,
        '-show_entries', 'format=duration',
        '-v', 'quiet',
        '-of', 'csv=p=0'
    ], capture_output=True, text=True)
    return float(result.stdout.strip())


# Function to encrypt chunks of video files
def encrypt_chunks(input_folder, output_folder, public_key):
    for filename in os.listdir(input_folder):
        # if filename.find('part_1_') != -1:
        #     continue
        if filename.endswith(".mp4"):
            input_file = filename
            input_file = os.path.join(input_folder, filename)
            # print("input file during encryption is ",input_file)
            encrypted_video = encrypt_video(input_file, public_key)
            encrypted_chunks_folder = os.path.join(output_folder, f'{os.path.basename(input_file)[:-4]}')
            encrypted_aes_key_folder = os.path.join('content/encrypted_aes_keys',
                                                    f'{os.path.basename(input_file)[:-4]}')

            # if not os.path.exists(encrypted_chunks_folder.split("_part_")[0]):
            #     os.makedirs(encrypted_chunks_folder)
            # if not os.path.exists(encrypted_aes_key_folder.split("_part_")[0]):
            #     os.makedirs(encrypted_aes_key_folder)
            if not os.path.exists(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}'):
                os.makedirs(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}')

            with open(output_folder + '/' + f'{os.path.basename(input_file)[:-4]}_encrypted_chunk.enc', 'wb') as f:
                f.write(encrypted_video)


# Function to decrypt chunks of video files
def decrypt_chunks(input_folder, output_folder, private_key):
    if not os.path.exists(f'content/derypted_chunks/{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}')

    # Iterate through all encrypted video chunks in the input folder
    for filename in os.listdir(input_folder):
        if filename.endswith(".enc"):
            input_file = os.path.join(input_folder, filename)
            output_file = os.path.join(output_folder, filename)
            output_file = output_file.replace("encrypted_chunk.enc", "decrypted_chunk.mp4")
            print("Decrypting: ", input_file)

            # Read encrypted chunk data
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt chunk data using RSA decryption
            decrypted_data = decrypt_video(encrypted_data, private_key)

            # Write decrypted data to output file
            # output_folder + '/' + f'{os.path.basename(input_file)[:-4]}_encrypted_chunk.enc'
            with open(output_file.replace("\\", "/"), 'wb') as f:
                f.write(decrypted_data)
            print(f'decryption for {input_file} complete! ===')


def combine_video_chunks(input_folder, output_file):
    # Check if the output folder exists, create it if not
    if not os.path.exists(os.path.dirname(output_file)):
        os.makedirs(os.path.dirname(output_file))

    # Get a list of all decrypted video chunk files
    input_files = [f for f in os.listdir(input_folder) if f.endswith('.mp4')]

    # Sort the files based on their numerical order
    input_files = sorted(input_files, key=lambda x: int(x.split('_part_')[1].split('_')[0]))

    # Create a temporary text file to hold the list of input files
    list_file = os.path.join(input_folder, 'file_list.txt')
    with open(list_file, 'w') as f:
        for file in input_files:
            f.write(f"file '{os.path.basename(file)}'\n")

    # Path to the combine_videos.py script in location B
    combine_script_path = input_folder + '/combine.sh'
    # Open source file for reading
    with open('combine.sh', 'rb') as src:
        # Open destination file for writing
        with open(combine_script_path, 'wb') as dest:
            # Read from source and write to destination
            dest.write(src.read())

    # Store the current working directory
    original_directory = os.getcwd()

    # Absolute path to the directory containing the script
    script_directory = os.path.abspath(combine_script_path)

    # Change working directory to the script directory
    os.chdir(os.path.dirname(script_directory))
    print("present working directory ", os.getcwd())

    # Execute the bash script
    subprocess.run(['C:\\Program Files\\Git\\bin\\bash.exe', 'combine.sh'],
                   check=True)

    os.chdir(original_directory)
    shutil.copy(input_folder + '/output_video.mp4', output_file)
    print(f"Combined video saved to: {output_file}")


def extract_number(filename):
    return int(filename.split('_part_')[1].split('_')[0])


def copy_file(source, destination):
    with open(source, 'rb') as f_source:
        with open(destination, 'wb') as f_dest:
            # Read and write in chunks to handle large files
            chunk_size = 1024
            while True:
                chunk = f_source.read(chunk_size)
                if not chunk:
                    break
                f_dest.write(chunk)


# Main function
if __name__ == "__main__":
    # Path to the original video file
    video_path = 'Videos/ishq.mp4'

    # Clean up any existing files in relevant directories
    delete_files_in_subfolders('content')
    if os.path.exists(f'chunks_of_{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'chunks_of_{os.path.basename(video_path)[:-4]}')

    delete_files_in_subfolders(f'content/decrypted_chunks/{os.path.basename(video_path)}')
    delete_files_in_subfolders(f'content/encrypted_chunks/{os.path.basename(video_path)}')
    folder_path = f'{os.path.basename(video_path)[:-4]}'
    delete_files_in_subfolders(folder_path)
    # os.remove('chunks_of_'+folder_path,true)

    startFull_time = time.time()
    # Define the paths to public and private keys
    public_key_path = 'keys/pubKey/public_key.pem'
    private_key_path = 'keys/privKey/private_key.pem'

    start_time = time.time()
    # Split the video into chunks and encrypt the first chunk
    split_video_ffmpeg(video_path, f'chunks_of_{os.path.basename(video_path)[:-4]}', 1, 10)
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Chunking time: {execution_time:.6f} seconds")

    start_time = time.time()
    # Encrypt the remaining chunks
    encrypt_chunks(f'chunks_of_{os.path.basename(video_path)[:-4]}',
                   f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}', public_key_path)
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Encryption time: {execution_time:.6f} seconds")
    # Decrypt the first chunk
    print("encrypt_chunks function complete !")

    start_time = time.time()
    # Decrypt the remaining chunks
    decrypt_chunks(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}',
                   f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}', private_key_path)
    print("os.path.basename(video_path) :", os.path.basename(video_path)[:-4])
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Encryption time: {execution_time:.6f} seconds")

    start_time = time.time()

    combine_video_chunks(f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}',
                         f'content/FinalVideo/{os.path.basename(video_path)[:-4]}/{os.path.basename(video_path)}')
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Decryption time: {execution_time:.6f} seconds")

    end_time = time.time()
    execution_time = end_time - startFull_time
    print(f"Complete Execution time: {execution_time:.6f} seconds")
