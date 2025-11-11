from flask import Flask, render_template
from flask_socketio import SocketIO, emit


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
port = 3000


@app.route('/')
def index():
    return render_template('index.html')


@socketio.on('send_message')
def handle_send(data):
    msg = data.get('message', '')

    emit('receive_message', {
        "message": msg,
    }, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, host='localhost', port=port, debug=True,  allow_unsafe_werkzeug=True)
