import os
from cryptography.hazmat.primitives import serialization


def read_pem_key_from_file(file_path, key_type):
    with open(file_path, 'rb') as key_file:
        if key_type == 'public':
            key = serialization.load_pem_public_key(key_file.read())
        elif key_type == 'private':
            key = serialization.load_pem_private_key(key_file.read(), password=b'abrar')
        else:
            raise ValueError("Invalid key type. Use 'public' or 'private'.")

    return key


def get_pem_key_pair_from_folders(public_key_folder, private_key_folder):
    public_key_path = get_pem_key_path(public_key_folder, 'public')
    private_key_path = get_pem_key_path(private_key_folder, 'private')

    if public_key_path and private_key_path:
        public_key = read_pem_key_from_file(public_key_path, 'public')
        private_key = read_pem_key_from_file(private_key_path, 'private')
        return public_key, private_key
    else:
        raise FileNotFoundError("Public and/or private key file(s) not found in the specified folders.")


def get_pem_key_path(folder_path, key_type):
    files = os.listdir(folder_path)

    if key_type == 'public':
        key_file = next((file for file in files if file.endswith('public_key.pem')), None)
    elif key_type == 'private':
        key_file = next((file for file in files if file.endswith('private_key.pem')), None)
    else:
        raise ValueError("Invalid key type. Use 'public' or 'private'.")

    if key_file:
        key_file_path = os.path.join(folder_path, key_file)
        return key_file_path
    else:
        return None


if __name__ == "__main__":
    public_key_folder_path = '/keys/pubKey/'  # Replace with the path to your public key folder
    private_key_folder_path = '/keys/privKey/'  # Replace with the path to your private key folder

    try:
        public_key, private_key = get_pem_key_pair_from_folders(public_key_folder_path, private_key_folder_path)
        print(f"Public key obtained: {public_key}")
        print(f"Private key obtained: {private_key}")

        # Now you can use the public_key and private_key as needed

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")
