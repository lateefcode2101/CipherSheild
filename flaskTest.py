import os
from flask import Flask, render_template, request, redirect, flash
from werkzeug.utils import secure_filename
from onlyEncryption import split_video_ffmpeg, encrypt_chunks, public_key_path

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Define the allowed file extensions for upload
ALLOWED_EXTENSIONS = {'mp4'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    # Check if the POST request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']

    # If the user does not select a file, the browser submits an empty file without a filename
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    # If the file is valid and allowed
    if file and allowed_file(file.filename):
        try:
            # Save the uploaded file to a temporary location
            filename = secure_filename(file.filename)
            file_path = os.path.join('Videos', filename)
            file.save(file_path)

            # Perform encryption process
            split_video_ffmpeg(file_path, f'chunks_of_{os.path.basename(file_path)[:-4]}')
            encrypt_chunks(f'chunks_of_{os.path.basename(file_path)[:-4]}', f'content/encrypted_chunks/{os.path.basename(file_path)[:-4]}', public_key_path)

            # Once encryption is done, show success message or redirect to results page
            flash('Encryption complete!')
            return redirect(request.url)
        except Exception as e:
            flash(f'An error occurred: {str(e)}')
            return redirect(request.url)

if __name__ == '__main__':
    app.run(debug=True)
