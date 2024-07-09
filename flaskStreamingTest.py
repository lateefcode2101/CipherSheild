from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, Response, request
import os

app = Flask(__name__)

# Define the key for encryption (change this to your own key)
KEY = b'sixteen byte key'  # 16 bytes for AES-128, 32 bytes for AES-256

@app.route('/video')
def stream_encrypted_video():
    # Path to the video file you want to stream
    video_path = 'Videos/ishq.mp4'

    # Open the video file in binary mode
    with open(video_path, 'rb') as video_file:
        video_data = video_file.read()

    # Split the video data into chunks
    chunk_size = 1024 * 1024  # 1 MB chunk size
    chunks = [video_data[i:i + chunk_size] for i in range(0, len(video_data), chunk_size)]

    # Encrypt each chunk using AES-GCM
    encrypted_chunks = []
    for chunk in chunks:
        iv = os.urandom(12)  # Generate a random IV (nonce) for each chunk
        cipher = Cipher(algorithms.AES(KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
        tag = encryptor.tag
        encrypted_chunks.append((iv, encrypted_chunk, tag))

    # Generate a response with the encrypted video chunks
    response = Response(stream_encrypted_data(encrypted_chunks), mimetype='video/mp4')

    # Set the proper headers to indicate streaming
    response.headers['Accept-Ranges'] = 'bytes'
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Content-Disposition'] = 'inline'
    response.headers['Connection'] = 'keep-alive'

    return response

def stream_encrypted_data(encrypted_chunks):
    for iv, encrypted_chunk, tag in encrypted_chunks:
        # Prepend the IV and tag to each encrypted chunk
        yield iv + tag + encrypted_chunk

if __name__ == '__main__':
    app.run(debug=True)
