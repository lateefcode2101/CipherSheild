from flask import Flask, Response
from Crypto.Cipher import AES
import os

app = Flask(__name__)

# Define the key and IV for encryption (change these to your own values)
KEY = b'sixteen byte key'
IV = b'InitializationVe'

@app.route('/video')
def stream_encrypted_video():
    # Path to the video file you want to stream
    video_path = 'Videos/getfit.mp4'

    # Open the video file in binary mode
    video_file = open(video_path, 'rb')

    # Read the video file data
    video_data = video_file.read()

    # Close the video file
    video_file.close()

    # Split the video data into chunks
    chunk_size = 1024 * 1024  # 1 MB chunk size
    chunks = [video_data[i:i + chunk_size] for i in range(0, len(video_data), chunk_size)]

    # Encrypt each chunk using AES-GCM
    encrypted_chunks = []
    print("chunks are ",len(chunks))
    for chunk in chunks:
        cipher = AES.new(KEY, AES.MODE_GCM, IV)
        encrypted_chunk, tag = cipher.encrypt_and_digest(chunk)
        encrypted_chunks.append(encrypted_chunk)

    # Generate a response with the encrypted video chunks
    response = Response(stream_encrypted_data(encrypted_chunks), mimetype='video/mp4')

    # Set the proper headers to indicate streaming
    response.headers['Accept-Ranges'] = 'bytes'
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Content-Disposition'] = 'inline'
    response.headers['Connection'] = 'keep-alive'

    return response

def stream_encrypted_data(encrypted_chunks):
    for chunk in encrypted_chunks:
        yield chunk

if __name__ == '__main__':
    app.run(debug=True)
