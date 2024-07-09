import hashlib
import os
import shutil
import subprocess
import time
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# from encryptVideoUsingAESandRSA import encrypt_video, decrypt_video, write_file, generate_aes_key
from ClearFolders import delete_files_in_subfolders

global_i = None
previous_aes_key = None

# Define the paths to public and private keys
public_key_path = 'keys/pubKey/public_key.pem'
private_key_path = 'keys/privKey/private_key.pem'
debug_flag=False

def generate_hash_of_system_info(system_time, process_id, machine_id):
    # Encode the system state information to utf-8
    system_time_encoded = str(system_time).encode('utf-8')
    process_id_encoded = str(process_id).encode('utf-8')
    machine_id_encoded = str(machine_id).encode('utf-8')

    # Concatenate the system state information
    concatenated_info = system_time_encoded + process_id_encoded + machine_id_encoded

    # Generate the SHA-256 hash of the concatenated information
    hashed_data = hashlib.sha256(concatenated_info).digest()

    return hashed_data

def verify_hash_of_system_info(known_hash, system_time, process_id, machine_id):
    # Generate the hash from the provided system-specific information
    generated_hash = generate_hash_of_system_info(system_time, process_id, machine_id)

    # Compare the known hash with the generated hash
    if generated_hash == known_hash:
        print("Verification successful: The generated hash matches the known hash.")
        return True
    else:
        print("Verification failed: The generated hash does not match the known hash.")
        return False

# Example usage:
# Assume the following values are used during encryption
system_time = time.time()  # Current system time
process_id = os.getpid()  # Current process ID
machine_id = uuid.uuid4()  # A unique identifier for the machine (e.g., UUID)

# Generate the known hash during encryption
known_hash = generate_hash_of_system_info(system_time, process_id, machine_id)

# Verify the hash of the system-specific information
verification_result = verify_hash_of_system_info(known_hash, system_time, process_id, machine_id)


# Function to decrypt video using RSA and AES-GCM
def decrypt_chunks(input_folder, output_folder, private_key):
    global debug_flag
    # Iterate through all encrypted video chunks in the input folder
    for filename in os.listdir(input_folder):
        if filename.endswith(".enc"):
            input_file = os.path.join(input_folder, filename)
            output_file = os.path.join(output_folder, filename)
            output_file = output_file.replace("encrypted_chunk.enc", "decrypted_chunk.mp4")
            print("\nDecrypting: ", input_file.replace("\\", "/"))

            # Read encrypted chunk data
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt chunk data using RSA decryption
            decrypted_data = decrypt_video(encrypted_data, private_key)

            # Write decrypted data to output file
            # output_folder + '/' + f'{os.path.basename(input_file)[:-4]}_encrypted_chunk.enc'
            with open(output_file.replace("\\", "/"), 'wb') as f:
                f.write(decrypted_data)
            if debug_flag:
                print(f'decryption for {input_file} complete! ===')


# Function to decrypt chunks of video files
def decrypt_video(encrypted_data, private_key_file):
    global debug_flag
    # Read the private key
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Determine the RSA key size in bytes
    rsa_key_size_in_bytes = private_key.key_size //8
    # print('key size in bytes is ',rsa_key_size_in_bytes)

    # Ensure the encrypted data is at least large enough to contain the AES key, nonce, tag, and video data
    if len(encrypted_data) < rsa_key_size_in_bytes + 16 + 16:
        raise ValueError(
            "Encrypted data is too short to contain the necessary components (AES key, nonce, tag, video data).")

        # Determine the size of the RSA key
    rsa_key_size_in_bytes = private_key.key_size // 8

    # Split the encrypted data into components: encrypted AES key, nonce, tag, and encrypted video data
    encrypted_aes_key = encrypted_data[:rsa_key_size_in_bytes]
    nonce = encrypted_data[rsa_key_size_in_bytes:rsa_key_size_in_bytes + 16]
    tag = encrypted_data[rsa_key_size_in_bytes + 16:rsa_key_size_in_bytes + 32]
    encrypted_video = encrypted_data[rsa_key_size_in_bytes + 32:-32]
    hash_check = encrypted_data[:len(encrypted_data) - 32]
    data_of_encrypted_data = encrypted_data[len(encrypted_data) - 32:]
    # print('len of hash check is ',data_of_encrypted_data)
    # print('len of hash calculated is ', hashlib.sha256(hash_check).digest())
    if data_of_encrypted_data == hashlib.sha256(hash_check).digest():
        if debug_flag:
            print("Verification successful: The generated hash matches the known hash.")
    else:
        if debug_flag:
            print("Verification Failed: The generated hash does not match the known hash.")

    # print('size of encrypted video is ',len(encrypted_video))
    # print(f'+++type of encrypted aes key is {type(encrypted_aes_key)} and nonce is {type(nonce)} and tag is {type(tag)} ')
    # print(f'len of encrypted_aes_key  is {len(encrypted_aes_key)}')
    # print(f'len of nonce  is {len(nonce)}')
    # print(f'len of tag  is {len(tag)}')
    # print(f'len of encrypted_video  is {len(encrypted_video)}')
    # print('len of private kye is ', len(str(private_key)))
    # print('len of encrypted_aes_key is ', len(encrypted_aes_key))
    # Decrypt the AES key using RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if debug_flag:
        print('aes key is ', aes_key)
    # print('nonce is ',nonce)
    # print('tag is ', tag)
    # print('size of aes ', len(aes_key))
    # print('size of nonce ', len(nonce))
    # print('size of tag ', len(tag))

    # Decrypt the video data using AES GCM
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher_aes.decryptor()
    # with open('bBytes.txt', 'rb') as f:
    #     fileData = f.read()
    # print('file data is \n',fileData)
    # #decryptor.authenticate_additional_data(fileData)
    decrypted_video = decryptor.update(encrypted_video) + decryptor.finalize()

    return decrypted_video


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

    # Store the current working directory
    original_directory = os.getcwd()

    # Absolute path to the directory containing the script
    script_directory = os.path.abspath(input_folder)

    # Change working directory to the script directory
    os.chdir(os.path.dirname(script_directory + f'/{os.path.basename(video_path)[:-4]}'))
    if debug_flag:
        print("present working directory ", os.getcwd())
    subprocess.run(
        ['E:\\installs\\ffmpeg\\bin\\ffmpeg.exe', '-y', '-f', 'concat', '-safe', '0',
         '-i', 'file_list.txt', '-c',
         'copy',
         'output_video.mp4'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    os.chdir(original_directory)
    # print("current directory is ", os.getcwd())
    # print("input_folder is ", input_folder.replace("/", "\\"))
    # print("output_file is ", output_file)
    shutil.copy(input_folder + '/output_video.mp4', output_file)
    print(f"Combined video saved to: {output_file}")


if __name__ == "__main__":
    startFull_time = time.time()
    # Path to the original video file
    video_path = 'Videos/test U2.mp4'
    # Clean up any existing files in relevant directories
    if not os.path.exists(f'chunks_of_{os.path.basename(video_path)[:-4]}'):
        os.makedirs(f'chunks_of_{os.path.basename(video_path)[:-4]}')

    folder_path = f'{os.path.basename(video_path)[:-4]}'
    delete_files_in_subfolders(folder_path)
    # os.remove('chunks_of_'+folder_path,true)
    start_time = time.time()
    # Decrypt the remaining chunks
    decrypt_chunks(f'content/encrypted_chunks/{os.path.basename(video_path)[:-4]}',
                   f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}', private_key_path)
    print("Basename of the video file :", os.path.basename(video_path)[:-4])
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Decryption time: {execution_time:.6f} seconds")

    start_time = time.time()
    combine_video_chunks(f'content/decrypted_chunks/{os.path.basename(video_path)[:-4]}',
                         f'content/FinalVideo/{os.path.basename(video_path)[:-4]}/{os.path.basename(video_path)}')
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Time to combine the chunks: {execution_time:.6f} seconds")

    end_time = time.time()
    execution_time = end_time - startFull_time
    print(f"Complete Execution time: {execution_time:.6f} seconds")
