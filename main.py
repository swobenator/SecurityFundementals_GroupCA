from flask import Flask, render_template
import flask_socketio

app = Flask(__name__, template_folder='templates')
port = 3000


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='localhost', port=port, debug=True)

