from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('reciever.html')

@app.route('/play', methods=['POST'])
def play():
    video_name = request.form.get('video_name')
    return render_template('play.html', video_name=video_name)

if __name__ == '__main__':
    app.run(debug=True)
