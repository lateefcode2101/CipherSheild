#Flask, render_template, request, send_file
import os

from flask import Flask, render_template, request, send_file

app = Flask(__name__)

# Path to the folder containing video files
VIDEO_FOLDER = 'videos'


@app.route('/')
def index():
    return render_template('sender.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file:
        # Save the uploaded file to the video folder
        file_path = os.path.join(VIDEO_FOLDER, file.filename)
        file.save(file_path)
        return 'File uploaded successfully'


@app.route('/send/<path:video_name>')
def send_video(video_name):
    video_path = os.path.join(VIDEO_FOLDER, video_name)
    if not os.path.exists(video_path):
        return 'Video not found'
    return send_file(video_path, mimetype='video/mp4')


if __name__ == '__main__':
    if not os.path.exists(VIDEO_FOLDER):
        os.makedirs(VIDEO_FOLDER)
    app.run(debug=True)
