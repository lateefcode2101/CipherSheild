import subprocess


def runProcessToConcatVideos():
    subprocess.run([
        'E:\\installs\\ffmpeg\\bin\\ffmpeg.exe', '-y',  # Overwrite output file if it exists
        '-f', 'concat',
        '-safe', '0',
        '-i', 'file_list.txt',
        '-c', 'copy',
        'output_video.mp4'
    ], check=True)
