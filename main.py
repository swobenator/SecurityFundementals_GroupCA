from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto import crypto

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
port = 3000

public, private, primes = crypto.create_keys()
VIG_KEY = "Bogdan"


@app.route('/')
def index():
    return render_template('index.html', private_key_d=private[0], private_key_n=private[1])


@socketio.on('send_message')
def handle_send(data):
    msg = data.get('message', '')
    username = data.get('username', 'Anonymous')

    vig_cipher, rsa_blocks = crypto.package_for_sender(msg, VIG_KEY, public)

    emit('receive_message', {
        "vig_ciphertext": vig_cipher,
        "rsa_key_blocks": rsa_blocks,
        "username": username
    }, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, host='localhost', port=port, debug=True,  allow_unsafe_werkzeug=True)
