from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
import uuid
import time
import base64
import jwt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Global Variables
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
numbers = private_key.private_numbers()

# Secret key for encryption and decryption
SECRET_KEY = os.getenv('NOT_MY_KEY', 'default_secret_key')

# Password hasher
ph = PasswordHasher()

# AES Encryption and Decryption functions
def aes_encrypt(data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(SECRET_KEY.encode()), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return base64.urlsafe_b64encode(cipher_text).decode()

def aes_decrypt(data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(SECRET_KEY.encode()), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.urlsafe_b64decode(data)) + decryptor.finalize()
    return decrypted_data

# Convert integer to base64    
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    
    return encoded.decode('utf-8')

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    date_registered = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    last_login = db.Column(db.TIMESTAMP)

# Authentication Log model
class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(50), nullable=False)
    request_timestamp = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('auth_logs', lazy=True))

# Private Key model
class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.Text, nullable=False)
    exp = db.Column(db.Integer, nullable=False)

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data or 'username' not in data or 'email' not in data:
            return jsonify({"error": "Invalid request"}), 400

        username = data['username']
        email = data['email']

        # Generate secure password using UUIDv4
        password = str(uuid.uuid4())

        # Hash the password using Argon2
        password_hash = ph.hash(password)

        # Store user details in the database
        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"password": password}), 201
    except Exception as e:
        app.logger.error("An error occurred during registration: %s", e)
        return jsonify({"error": "Internal Server Error"}), 500

# Endpoint for authentication and signed JWT
@app.route('/auth', methods=['POST'])
def auth():
    try:
        data = request.json
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Invalid request"}), 400

        username = data['username']
        password = data['password']

        # Log authentication request
        request_ip = request.remote_addr
        user = User.query.filter_by(username=username).first()
        if user:
            new_log = AuthLog(request_ip=request_ip, user=user)
            db.session.add(new_log)
            db.session.commit()

        # Retrieve user's hashed password
        stored_password_hash = user.password_hash if user else None

        if stored_password_hash:
            try:
                # Verify password
                ph.verify(stored_password_hash, password)
            except VerifyMismatchError:
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            return jsonify({"error": "User not found"}), 404

        # Retrieve private key from the database
        private_key_obj = Key.query.filter(Key.exp > int(time.time())).first()
        if private_key_obj:
            private_pem = aes_decrypt(private_key_obj.key)
            private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
        else:
            return jsonify({"error": "Private key not found"}), 404

        headers = {"kid": "goodKID"}
        token_payload = {"user": username, "exp": time.time() + 3600}
        token = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
        return token, 200
    except Exception as e:
        app.logger.error("An error occurred during authorization: %s", e)
        return jsonify({"error": "Internal Server Error"}), 500

# Endpoint to connect JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    keys = {
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": "goodKID",
                "n": int_to_base64(numbers.public_numbers.n),
                "e": int_to_base64(numbers.public_numbers.e),
            }
        ]
    }
    return jsonify(keys)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(port=8080, debug=True)
