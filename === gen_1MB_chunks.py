import os
import subprocess
import re


def get_video_duration(input_file):
    result = subprocess.run([
        'E:\\installs\\ffmpeg\\bin\\ffprobe.exe',
        '-i', input_file,
        '-show_entries', 'format=duration',
        '-v', 'quiet',
        '-of', 'csv=p=0'
    ], capture_output=True, text=True)

    return float(result.stdout.strip())


def split_video_ffmpeg(input_file, output_folder, target_chunk_size_MB):
    # Check if the output folder exists, create it if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get the total size of the input video file
    total_size = os.path.getsize(input_file)

    # Define the target chunk size in bytes
    target_chunk_size_bytes = target_chunk_size_MB * 1024 * 1024  # Convert MB to bytes

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


if __name__ == "__main__":
    video_path = 'Videos/Original_chunking_Video.mp4'  # Replace with the path to your video file
    target_chunk_size_MB = 1  # Specify the target size of each chunk in megabytes

    split_video_ffmpeg(video_path, ''.join(["chunks_of_", video_path])[:-4], target_chunk_size_MB)
