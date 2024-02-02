import os


def get_pem_key_pair_from_folder(folder_path, key_type):
    # List files in the specified folder
    files = os.listdir(folder_path)

    if key_type == 'public':
        public_key_file = next((file for file in files if file.endswith('public_key.pem')), None)
        if public_key_file:
            # If public key file is found, return its path
            public_key_path = os.path.join(folder_path, public_key_file)
            return public_key_path

    elif key_type == 'private':
        private_key_file = next((file for file in files if file.endswith('private_key.pem')), None)
        if private_key_file:
            # If private key file is found, return its path
            private_key_path = os.path.join(folder_path, private_key_file)
            return private_key_path

    # If any of the key files is missing, raise an exception
    raise FileNotFoundError(f"{key_type.capitalize()} key file not found in the specified folder.")


if __name__ == "__main__":
    public_key_folder_path = '/keys/pubKey/'  # Replace with the path to your public key folder
    private_key_folder_path = '/keys/privKey/'  # Replace with the path to your private key folder

    try:
        public_key_path = get_pem_key_pair_from_folder(public_key_folder_path, 'public')
        print(f"Public key found: {public_key_path}")
        print(public_key_path)

        private_key_path = get_pem_key_pair_from_folder(private_key_folder_path, 'private')
        print(f"Private key found: {private_key_path}")

        # Now you can use the private_key_path and public_key_path as needed

    except FileNotFoundError as e:
        print(f"Error: {e}")
        # Handle the exception as needed, for example, exit the script or take other appropriate actions
