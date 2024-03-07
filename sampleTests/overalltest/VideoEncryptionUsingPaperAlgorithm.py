import base64
import os
import subprocess
import re
import time
from cryptography.hazmat.primitives import serialization
from encryptFirstChunk import chunk
from ClearFolders import delete_files_in_subfolders
from encryptDecryptRemainingChunks import encrypt_video, decrypt_video, encrypt_chunks, decrypt_chunks


def load_public_key_from_pem_file(file_path):
    with open(file_path, "rb") as key_file:
        public_key = key_file.read()
        public_key_obj = serialization.load_pem_public_key(public_key)
        return public_key_obj


def get_video_duration(input_file):
    result = subprocess.run([
        'E:\\installs\\ffmpeg\\bin\\ffprobe.exe',
        '-i', input_file,
        '-show_entries', 'format=duration',
        '-v', 'quiet',
        '-of', 'csv=p=0'
    ], capture_output=True, text=True)
    return float(result.stdout.strip())


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


def split_video_ffmpeg(input_file, output_folder, target_chunk_size_MB_param):
    # Check if the output folder exists, create it if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get the total size of the input video file
    total_size = os.path.getsize(input_file)

    # Define the target chunk size in bytes
    target_chunk_size_bytes = target_chunk_size_MB_param * 1024 * 1024  # Convert MB to bytes

    # Calculate the number of chunks needed
    num_chunks = total_size // target_chunk_size_bytes + (total_size % target_chunk_size_bytes > 0)

    # Get video duration using ffprobe
    duration = get_video_duration(input_file)

    # Use FFmpeg to split the video into consecutive chunks of 1MB each
    for i in range(num_chunks):
        output_file = os.path.join(output_folder,
                                   f'{os.path.splitext(os.path.basename(input_file))[0]}_part_{i + 1}.mp4')
        print("output file: ", output_file)

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
        if i == 0:
            save_first_video_chunk_bytes(i, output_file, action='encrypt')
        if i > 0:
            encrypt_chunks(output_folder,
                           output_folder=os.path.join('content/encrypted_chunks/',
                                                      f'{os.path.splitext(os.path.basename(input_file))[0]}'),
                           public_key='keys/pubKey/public_key.pem')


def get_vid():
    with open('content/Vid/VID.txt', "rb") as fwrite16:
        vid_data = fwrite16.read()
    return vid_data


def decryptFirstChunk(output_file):
    print("output file while decrypting: ", output_file)
    chunk('decrypt', output_file)


if __name__ == "__main__":
    folder_path = 'content'  # Replace 'path_to_your_folder' with the actual folder path
    delete_files_in_subfolders(folder_path)
    folder_path = 'chunks_of_Original_chunking_Video'  # Replace 'path_to_your_folder' with the actual folder path
    delete_files_in_subfolders(folder_path)
    folder_path = 'chunks_of_Videos'  # Replace 'path_to_your_folder' with the actual folder path
    delete_files_in_subfolders(folder_path)

    # initializations of variables
    video_path = 'Videos/copy_of_Original_chunking_Video.mp4'  # Replace with the path to your video file
    target_chunk_size_MB = 1  # Specify the target size of each chunk in megabytes
    print("Video path is ", video_path)
    print("join statement is : ", ''.join(["chunks_of_", video_path])[:-4])
    split_video_ffmpeg(video_path, ''.join(["chunks_of_", video_path])[:-4], target_chunk_size_MB)
    print("\nSplitting complete\n")
    vid = get_vid()
    print("Vid is ", vid)

    decryptFirstChunk(f'content/encrypted_chunks/{os.path.basename(video_path)}')

    print("decryption complete")
