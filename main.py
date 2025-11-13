# Impors Flask for web framework and render_template for serving HTML pages
from flask import Flask, render_template
# Imports SocketIO for real-time communication and emit for event handling
from flask_socketio import SocketIO, emit
# imports the custom crypto module that handles encryption/decryption logic
from crypto import crypto

#Initialize the Flask app
app = Flask(__name__)

# Initialize SocketIO with CORS enabled
# This allows connections from any origin
socketio = SocketIO(app, cors_allowed_origins="*")

# Define the port the app will run on
port = 3000

# generate RSA public/private key pairs using the crypto module
public, private, primes = crypto.create_keys()

# define a static Vigenère cipher key (used to encrypt messages before RSA-encrypting the key)
VIG_KEY = "Bogdan"


# Flask route for the homepage, renders index.html when visiting
@app.route('/')
def index():
    # Pass RSA private key components (d, n) to the template
    return render_template('index.html', private_key_d=private[0], private_key_n=private[1])


# Socket.IO event handler for when a client sends a message
@socketio.on('send_message')
def handle_send(data):
    # Extract message and username from the data payload sent by the client
    msg = data.get('message', '')
    username = data.get('username', 'Anonymous')

    # Encrypt the message using Vigenere, then encrypt the Vigenere key using RSA
    vig_cipher, rsa_blocks = crypto.package_for_sender(msg, VIG_KEY, public)

    # broadcast the encrypted message and username to all connected clients
    emit('receive_message', {
        "vig_ciphertext": vig_cipher,    # Vigenere-encrypted message
        "rsa_key_blocks": rsa_blocks,    # RSA-encrypted Vigenère key
        "username": username             #Sender’s username
    }, broadcast=True)


# Run the Flask-SocketIO app
if __name__ == '__main__':
    # The app runs locally on port 3000 with debugging enabled
    #'allow_unsafe_werkzeug=True' bypasses a safety restriction for dev use only
    socketio.run(app, host='localhost', port=port, debug=True, allow_unsafe_werkzeug=True)
