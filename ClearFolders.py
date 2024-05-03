import os

debug_flag = False
def delete_files_in_subfolders(folder):
    global debug_flag
    for root, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.remove(file_path)
                if debug_flag:
                    print(f"Deleted file: {file_path}")
            except Exception as e:
                if debug_flag:
                    print(f"Error deleting file {file_path}: {e}")


if __name__ == "__main__":
    folder_path = 'content'  # Replace 'path_to_your_folder' with the actual folder path
    delete_files_in_subfolders(folder_path)
