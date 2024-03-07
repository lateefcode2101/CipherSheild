import os
import subprocess

video_path = 'Videos/bigVideo.mp4'

# Directory path
directory = f'content\\decrypted_chunks\\{os.path.basename(video_path)[:-4]}'

# Get list of files in the directory
files = os.listdir(directory)

# Sort files based on their part numbers
sorted_files = sorted(files, key=lambda x: int(x.split('_part_')[-1].split('_')[0]) if '_part_' in x else float('inf'))

# Write the list of files to a temporary text file
filelist_path = os.path.abspath(
    f'content\\decrypted_chunks\\{os.path.basename(video_path)[:-4]}\\FilesList\\filelist.txt')
with open(filelist_path, 'w') as f:
    for file in sorted_files:
        if file.endswith(".mp4"):  # Assuming the files are MP4 videos, adjust accordingly if needed
            f.write(f"file '{file}'\n")

# Concatenate videos using ffmpeg
subprocess.run(['ffmpeg', '-f', 'concat', '-safe', '0', '-i', filelist_path, '-c', 'copy',
                os.path.join(directory, 'final_video.mp4')])

# Remove the temporary filelist.txt
# os.remove(filelist_path)
