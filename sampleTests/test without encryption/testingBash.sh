#!/bin/bash

input_file="Tiger_3_2023_Hindi_Full_Movie_HDRip-(Filmywap.pm).mp4"
output_folder="bash_chunks"
target_chunk_size_MB=1

# Check if the output folder exists, create it if not
mkdir -p "$output_folder"

# Get the total size of the input video file
total_size=$(stat -c %s "$input_file")

# Define the target chunk size in bytes
target_chunk_size_bytes=$((target_chunk_size_MB * 1024 * 1024))

# Calculate the number of chunks needed
num_chunks=$(( (total_size + target_chunk_size_bytes - 1) / target_chunk_size_bytes ))

# Get video duration using ffprobe
duration=$(ffprobe -i "$input_file" -show_entries format=duration -v quiet -of csv=p=0)

# Use FFmpeg to split the video into consecutive chunks of 1MB each
for ((i=0; i<num_chunks; i++)); do
    output_file="$output_folder/part_$((i + 1)).mp4"

    # Calculate the start position for the current chunk
    start_position=$((i * target_chunk_size_bytes))

    # Run FFmpeg command to create the chunk based on the start position and size
    start_position_seconds=$(awk "BEGIN {printf \"%.6f\", $start_position / $total_size * $duration}")
    ffmpeg -i "$input_file" -c copy -map 0 -ss "$start_position_seconds" -fs "$target_chunk_size_bytes" "$output_file"
done
