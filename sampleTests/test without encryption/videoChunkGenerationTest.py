import os
import subprocess


def split_video_ffmpeg(input_file, output_folder, target_chunk_size_MB):
    # Check if the output folder exists, create it if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Get the total size of the input video file
    total_size = os.path.getsize(input_file)

    # Calculate the number of chunks needed
    target_chunk_size_bytes = target_chunk_size_MB * 1024 * 1024  # Convert MB to bytes
    num_chunks = total_size // target_chunk_size_bytes + (total_size % target_chunk_size_bytes > 0)

    # Use FFmpeg to split the video into chunks with a specific size
    for i in range(num_chunks):
        output_file = os.path.join(output_folder, f'part_{i + 1}.mp4')

        # Calculate the start time and duration for each chunk
        start_time = i * 2  # Assuming keyframes every 2 seconds; adjust as needed
        duration = 2  # Duration of each chunk in seconds; adjust as needed

        # Run FFmpeg command to create the chunk, seeking to the nearest keyframe
        subprocess.run(['E:\\installs\\ffmpeg\\bin\\ffmpeg.exe', '-i', input_file, '-c', 'copy', '-map', '0', '-ss',
                        f'{start_time}', '-t', f'{duration}', output_file], check=True)


if __name__ == "__main__":
    video_path = '../Original_chunking_Video.mp4'  # Replace with the path to your video file
    target_chunk_size_MB = 1  # Specify the target size of each chunk in megabytes

    split_video_ffmpeg(video_path, 'chunks', target_chunk_size_MB)
