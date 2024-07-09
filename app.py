from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from flask_mysqldb import MySQL
import bcrypt
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'asdf'
app.config['MYSQL_DB'] = 'cryptdb'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB

mysql = MySQL(app)


@app.route('/')
def index():
    if 'username' not in session:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT Videos.video_id, Videos.title, Videos.description, Videos.file_name
        FROM Videos
        JOIN Users ON Videos.recipient_id = Users.user_id
        WHERE Users.username = %s
    """, (username,))
    videos = cur.fetchall()
    cur.close()
    return render_template('index.html', videos=videos)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM Users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            stored_password_hash = user[3]
            if isinstance(stored_password_hash, str):
                stored_password_hash = stored_password_hash.encode('utf-8')
            if bcrypt.checkpw(password, stored_password_hash):
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'danger')
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        recipient_username = request.form['recipient']
        video_file = request.files['video_file']

        if video_file:
            video_file_data = video_file.read()
            file_name = video_file.filename

            cur = mysql.connection.cursor()
            cur.execute("SELECT user_id FROM Users WHERE username = %s", (recipient_username,))
            recipient = cur.fetchone()

            if recipient:
                uploader_username = session['username']
                cur.execute("SELECT user_id FROM Users WHERE username = %s", (uploader_username,))
                uploader = cur.fetchone()
                #----logic for encryption
                cur.execute(
                    "INSERT INTO Videos (title, description, video, file_name, uploader_id, recipient_id) VALUES (%s, %s, %s, %s, %s, %s)",
                    (title, description, video_file_data, file_name, uploader[0], recipient[0]))
                mysql.connection.commit()
                cur.close()
                flash('Video uploaded successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Recipient username not found', 'danger')
        else:
            flash('Please select a video file to upload.', 'warning')
    return render_template('upload.html')


@app.route('/video/<int:video_id>')
def video(video_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT video FROM Videos WHERE video_id = %s", (video_id,))
    video = cur.fetchone()
    cur.close()

    if video:
        return Response(video[0], mimetype='video/mp4')
    else:
        flash('Video not found', 'danger')
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
