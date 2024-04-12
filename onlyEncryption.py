import base64
import hashlib
import math
import os
import subprocess
import time
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# from flaskTest import file_path
from ClearFolders import delete_files_in_subfolders

# from overallTest import generate_x_coordinate, save_vid, get_mac_address, get_vid, copy_file, extract_number, \
#     encrypt_chunks, get_video_duration, split_video_ffmpeg, read_file, generate_aes_key_with_ecc, int_to_base64, \
#     ecc_generate_key, encrypt_video, write_file, generate_required_content_folders

global_i = None
previous_aes_key = None

# Define the paths to public and private keys
public_key_path = 'keys/pubKey/public_key.pem'
private_key_path = 'keys/privKey/private_key.pem'
a = 0
i = 0


def int_to_base64(integer):
    """
    :param integer: takes in integer values
    :return: returns base64 encoded string
    """
    # Convert integer to bytes
    integer_bytes = integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='big')
    # Encode bytes to Base64
    base64_encoded = base64.b64encode(integer_bytes)
    return base64_encoded


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


def get_vid():
    with open(f'content/Vid/{os.path.basename(video_path)[:-4]}/Vid.txt', "rb") as fwrite16:
        vid_data = fwrite16.read()
    return vid_data


def split_video_ffmpeg(input_file, output_folder):
    generate_required_content_folders(input_file)
    # Clean up any existing files in relevant directories
    delete_files_in_subfolders('content')
    delete_files_in_subfolders(f'chunks_of_{os.path.basename(input_file)[:-4]}')

    if not os.path.exists(f'chunks_of_{os.path.basename(input_file)[:-4]}'):
        os.makedirs(f'chunks_of_{os.path.basename(input_file)[:-4]}')

    delete_files_in_subfolders(f'content/decrypted_chunks/{os.path.basename(input_file)}')
    delete_files_in_subfolders(f'content/encrypted_chunks/{os.path.basename(input_file)}')
    folder_path = f'{os.path.basename(input_file)[:-4]}'
    delete_files_in_subfolders(input_file)

    # Check if the output folder exists, create it if not
    print("FIle path is: ", input_file)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get the total size of the input video file
    total_size = os.path.getsize(input_file)

    # Define the target chunk size in bytes
    target_chunk_size_bytes = 1 * 1024 * 1024  # Convert MB to bytes

    # Calculate the number of chunks needed
    num_chunks = total_size // target_chunk_size_bytes + (total_size % target_chunk_size_bytes > 0)
    print("num of chunks ", num_chunks)
    # Get video duration using ffprobe
    duration = get_video_duration(input_file)
    print("Duration of video is: ", duration)

    # Calculate the duration of each chunk in seconds
    chunk_duration_seconds = duration / num_chunks
    print("chunk_duration_seconds is ", chunk_duration_seconds)
    start_time_seconds = 0

    # Use FFmpeg to split the video into consecutive chunks of target_chunk_size_MB_param MB each
    for i in range(num_chunks):
        start_time_for = time.time()
        output_file = os.path.join(output_folder,
                                   f'{os.path.splitext(os.path.basename(input_file))[0]}_part_{i + 1}.mp4')
        print("\nfor output file: ", output_file)

        # Calculate the start and end timestamps for the current chunk
        end_time_seconds = min(start_time_seconds + chunk_duration_seconds, duration)
        print(f'start time is {start_time_seconds} and end time is {end_time_seconds}')
        # print("input file for ffmpeg is ",input_file)
        # Run FFmpeg command to create the chunk
        subprocess.run([
            'E:\\installs\\ffmpeg\\bin\\ffmpeg.exe',
            '-i', input_file,
            # '-c', 'copy',
            '-ss', str(start_time_seconds),  # Start timestamp
            '-to', str(end_time_seconds),  # End timestamp
            output_file
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("subprocess run complete")
        start_time_seconds = end_time_seconds
        print('i is ', i)
        if i == 0:
            first_part_file = output_file
            print(os.path.basename(first_part_file))
            # save_vid(first_part_file,video_path)
            print('in save vid')
            if os.path.exists(first_part_file):
                print('file available')

            with open(first_part_file, 'rb') as f:
                first_chunk_data = f.read()
                print('first chunk data read')
                exclamation_position = first_chunk_data.find(b'!')

                # Ensure "!" is found before attempting to extract bytes
                if exclamation_position != -1:
                    print('in exclamation')
                    # Extract the 16 bytes after the occurrence of "!"
                    extracted_bytes = first_chunk_data[
                                      exclamation_position + len('!'): exclamation_position + len('!') + 16]
                    print('before extracted bytes')
                    extracted_bytes_base64 = base64.b64encode(extracted_bytes).rstrip(b'=')
                    print("video_path is: ", video_path)
                    with open(f'content/Vid/{os.path.basename(video_path)[:-4]}/VID.txt', "wb") as fwrite_base64:
                        fwrite_base64.write(extracted_bytes_base64)

            print('save vid complete')
        end_time_for = time.time()
        execution_time_for = end_time_for - start_time_for
        print(f"\nChunking time of {os.path.basename(output_file)} is: {execution_time_for:.6f} seconds\n\n")


# def save_vid(first_chunk_file,video_path):
# print('in save vid')
# if os.path.exists(first_chunk_file):
#     print('file available')
#
# with open(first_chunk_file, 'rb') as f:
#     first_chunk_data = f.read()
#     print('first chunk data read')
#     exclamation_position = first_chunk_data.find(b'!')
#
#     # Ensure "!" is found before attempting to extract bytes
#     if exclamation_position != -1:
#         # Extract the 16 bytes after the occurrence of "!"
#         extracted_bytes = first_chunk_data[exclamation_position + len('!'): exclamation_position + len('!') + 16]
#         extracted_bytes_base64 = base64.b64encode(extracted_bytes).rstrip(b'=')
#         print("video_path is: ", video_path)
#         with open(f'content/Vid/{os.path.basename(video_path)[:-4]}/VID.txt', "wb") as fwrite_base64:
#             fwrite_base64.write(extracted_bytes_base64)


def encrypt_video(video_file, public_key_file):
    global previous_aes_key
    # Read the video file
    video_data = read_video_file(video_file)
    aes_key = generate_aes_key_with_ecc_equation()

    # store aes key for next chunk
    previous_aes_key = aes_key

    # Generate a random nonce
    nonce = os.urandom(16)

    # Encrypt the video data using AES GCM
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher_aes.encryptor()
    encrypted_video = encryptor.update(video_data) + encryptor.finalize()
    tag = encryptor.tag

    # Read the public key
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    # print('size of public key is ',len(public_key))

    # Encrypt the AES key using RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'len of encrypted_aes_key  is {len(encrypted_aes_key)}')
    print(f'len of nonce  is {len(nonce)}')
    print(f'len of tag  is {len(tag)}')
    print(f'len of encrypted_video  is {len(encrypted_video)}')

    # Combine encrypted AES key, nonce, tag, and encrypted video data
    encrypted_data = encrypted_aes_key + nonce + tag + encrypted_video
    print(f'len of encrypted_data  is {len(encrypted_data)}')

    previous_aes_key = aes_key

    return encrypted_data


# Function to encrypt chunks of video files
def encrypt_chunks(input_folder, output_folder, public_key):
    global global_i
    for filename in os.listdir(input_folder):
        if filename.find('part_1_') != -1:
            global_i = 1
        if filename.find('part_1_') == -1:
            global_i = 0
        if filename.endswith(".mp4"):
            input_file = os.path.join(input_folder, filename)
            # print("input file during encryption is ",input_file)
            encrypted_video = encrypt_video(input_file, public_key)

            if not os.path.exists(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}'):
                os.makedirs(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}')
            print("Before writing file")

            with open(output_folder + '/' + f'{os.path.basename(input_file)[:-4]}_encrypted_chunk.enc', 'wb') as f:
                f.write(encrypted_video)
            print("after writing file")


def read_video_file(file_path):
    with open(file_path, 'rb') as f:
        fileData = f.read()
    return fileData


def generate_aes_key_with_ecc_equation():
    ecc_key = generate_integer_from_ecc_equation()
    ecc_key_base64 = int_to_base64(ecc_key)
    print("Ecc key in use is: ", ecc_key_base64)

    # Hash the ECC key to generate an AES key of appropriate size
    aes_key = hashlib.sha256(ecc_key_base64).digest()
    print('length of aes key before truncating is ', len(aes_key))

    # Truncate the key to 16 bytes (128 bits) if needed
    aes_key = aes_key[:32]

    return aes_key


def generate_b_from_system_specific_data():
    # Collect system-specific information
    system_time = str(time.time()).replace(".", "").encode()  # Current system time
    print('system time is ', system_time)
    process_id = str(os.getpid()).encode()  # Process ID
    print('process id is ', process_id)
    machine_id = str(uuid.uuid4()).replace("-", "").encode()  # Machine ID (example: user ID)
    print('machine id is ', machine_id)

    # Concatenate and hash the collected information
    data_to_hash = b''.join([system_time, process_id, machine_id])
    print('system state information looks like this: ', data_to_hash)
    hashed_data = hashlib.sha256(data_to_hash).digest()

    # Convert the hash to an integer for use as the x-coordinate
    x_coordinate = int.from_bytes(hashed_data, byteorder='big')

    return x_coordinate


def generate_integer_from_ecc_equation():
    # generate the x coordinate of ecc equation
    x = int.from_bytes(os.urandom(32), byteorder='big')

    b = generate_b_from_system_specific_data()
    print("size of x is: ", len(str(x)))

    # if first chunk get the value of a from VID
    if global_i == 1:
        a = int.from_bytes(get_vid(), 'big')
    else:
        a = int.from_bytes(str(previous_aes_key).encode(), 'big')
    # Compute the RHS of the ECC equation
    rhs = x ** 3 + a * x + b

    # Compute the square root of the RHS
    y = int(math.isqrt(rhs))

    return y




# Function to encrypt video using AES-GCM and RSA
def generate_required_content_folders(video_path):
    if not os.path.exists('content'):
        os.makedirs('content')
    if not os.path.exists('content/decrypted_chunks'):
        os.makedirs('content/decrypted_chunks')
    if not os.path.exists('content/encrypted_chunks'):
        os.makedirs('content/encrypted_chunks')
    if not os.path.exists('content/Vid'):
        os.makedirs('content/Vid')
    if not os.path.exists('content/FinalVideo'):
        os.makedirs('content/FinalVideo')
    if not os.path.exists(f'content/Vid/{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'content/Vid/{os.path.basename(video_path)[:-4]}')
    if not os.path.exists(f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}')
    if not os.path.exists(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}')


def get_mac_address():
    mac = uuid.getnode()
    return ''.join(("%012X" % mac)[i:i + 2] for i in range(0, 12, 2))


if __name__ == "__main__":
    # Path to the original video file
    video_path = 'Videos/numbersCount.mp4'
    generate_required_content_folders(video_path)
    # Clean up any existing files in relevant directories
    delete_files_in_subfolders('content')
    delete_files_in_subfolders(f'chunks_of_{os.path.basename(video_path)[:-4]}')

    if not os.path.exists(f'chunks_of_{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'chunks_of_{os.path.basename(video_path)[:-4]}')

    delete_files_in_subfolders(f'content/decrypted_chunks/{os.path.basename(video_path)}')
    delete_files_in_subfolders(f'content/encrypted_chunks/{os.path.basename(video_path)}')
    folder_path = f'{os.path.basename(video_path)[:-4]}'
    delete_files_in_subfolders(folder_path)
    # os.remove('chunks_of_'+folder_path,true)

    startFull_time = time.time()

    start_time = time.time()
    # Split the video into chunks and encrypt the first chunk
    split_video_ffmpeg(video_path, f'chunks_of_{os.path.basename(video_path)[:-4]}')
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"\n == Chunking time: {execution_time:.6f} seconds")
    # Coefficient 'a' in the equation y^2 = x^3 + a*x + b
    # b = int.from_bytes(get_mac_address().encode(), 'big')  # Coefficient 'b' in the equation y^2 = x^3 + a*x + b

    start_time = time.time()
    # Encrypt the remaining chunks
    encrypt_chunks(f'chunks_of_{os.path.basename(video_path)[:-4]}',
                   f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}', public_key_path)
    end_time = time.time()
    execution_time = end_time - start_time
    print(f" == Encryption time: {execution_time:.6f} seconds")
    # Decrypt the first chunk
    print("encrypt_chunks function complete !")

