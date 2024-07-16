import os

def rename_files(folder_path):
  """
  Renames all files in a folder to their respective file sizes in MB.

  Args:
    folder_path: Path to the folder containing the files to rename.
  """
  for filename in os.listdir(folder_path):
    filepath = os.path.join(folder_path, filename)
    if os.path.isfile(filepath):
      filesize = os.path.getsize(filepath) / (1024 * 1024)  # Convert bytes to MB
      new_filename = f"S_{round(filesize, 2):.2f}.{os.path.splitext(filename)[1]}"  # Format with 2 decimal places
      counter = 1
      while os.path.exists(os.path.join(folder_path, new_filename)):
        new_filename = f"S_{round(filesize, 2):.2f}_{counter}.{os.path.splitext(filename)[1]}"
        counter += 1
      os.rename(filepath, os.path.join(folder_path, new_filename))

# Example usage
folder_path = "Videos"
rename_files(folder_path)

print("Files renamed successfully!")
