import os

from encryptFirstChunk import save_tag, save_nonce
from encryptVideoUsingAESandRSA import encrypt_video, decrypt_video, write_file


def encrypt_chunks(input_folder, output_folder, public_key):
    # Iterate through all video chunks in the input folder
    print('input folder is ', input_folder)
    for filename in os.listdir(input_folder):
        if filename.find('part_1_'):
            pass
        if filename.endswith(".mp4"):
            input_file = os.path.join(input_folder, filename)
            # output_file =f'content/encrypted_chunks/{os.path.basename(input_folder)}_part_1/'+f'{os.path.basename(filename)[:-4]}_encrypted_chunk.enc'
            #
            # print("reading input file: ",input_file)
            #
            # # Encrypt chunk data using RSA encryption
            # encrypted_data = encrypt_video(input_file, public_key)
            # print("output_file for chunk: ",output_file)
            # # Write encrypted data to output file
            # with open(output_file, 'wb') as f:
            #     f.write(encrypted_data)
            # Encrypt the video file
            encrypted_aes_key, encrypted_video, nonce, tag = encrypt_video(input_file, public_key)
            print("encrypted aes key during encryption is :\n", encrypted_aes_key)

            # Create directories to save encrypted chunks and AES key if they don't exist
            encrypted_chunks_folder = f'content/encrypted_chunks/{os.path.basename(input_file)[:-4]}'
            encrypted_aes_key_folder = f'content/encrypted_aes_keys/{os.path.basename(input_file)[:-4]}'
            encrypted_folder = 'content/encrypted_chunks'

            if not os.path.exists(encrypted_chunks_folder):
                os.makedirs(encrypted_chunks_folder)
            if not os.path.exists(encrypted_aes_key_folder):
                os.makedirs(encrypted_aes_key_folder)

            # Save nonce and tag to a file
            save_tag(tag)
            save_nonce(nonce)

            # Save the encrypted AES key and the encrypted video
            write_file(encrypted_aes_key,
                       os.path.join(encrypted_aes_key_folder,
                                    f'{os.path.basename(input_file)[:-4]}_encrypted_aes_key.enc'))
            write_file(encrypted_video,
                       os.path.join(encrypted_chunks_folder,
                                    f'{os.path.basename(input_file)[:-4]}_encrypted_chunk.enc'))


def decrypt_chunks(input_folder, output_folder, private_key):
    # Iterate through all encrypted video chunks in the input folder

    for filename in os.listdir(input_folder):
        if filename.find('part_1_'):
            pass
        if filename.endswith(".mp4"):
            input_file = os.path.join(input_folder, filename)
            output_file = os.path.join(output_folder, filename)
            print("decrypting: ", input_file)

            # Read encrypted chunk data
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt chunk data using RSA decryption
            decrypted_data = decrypt_video(encrypted_data, private_key)

            # Write decrypted data to output file
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
