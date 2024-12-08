from flask import Flask, request, jsonify
import hashlib
import os
import base64

app = Flask(__name__)

class Bcrypt:
    def __init__(self, rounds=12, salt_length=22):
        self.rounds = rounds
        self.salt_length = salt_length

    def generate_salt(self, salt_length=None):
        if salt_length is None:
            salt_length = self.salt_length
        return base64.b64encode(os.urandom(salt_length)).decode('utf-8')[:salt_length]

    def bcrypt_hash(self, password, salt, cost):
        password_salt = f'{password}{salt}'
        password_salt = password_salt.encode('utf-8')
        hashed_password_salt = hashlib.sha256(password_salt).hexdigest()
        for _ in range(2**cost):
            hashed_password_salt = hashlib.sha256(hashed_password_salt.encode('utf-8')).hexdigest()
        return hashed_password_salt

    def hash_password(self, password, salt_length=None, cost=None):
        if salt_length is None:
            salt_length = self.salt_length
        if cost is None:
            cost = self.rounds
        salt = self.generate_salt(salt_length)
        hashed_password = self.bcrypt_hash(password, salt, cost)
        return f'{cost}${salt}${hashed_password}'

    def verify_password(self, password, hashed_password):
        cost, salt, hashed_password = hashed_password.split('$')
        cost = int(cost)
        return hashed_password == self.bcrypt_hash(password, salt, cost)


users_db = {}
bcrypt = Bcrypt()


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = bcrypt.hash_password(password)
    users_db[username] = hashed_password

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/users')
def users():
    return jsonify(users_db)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    stored_hash = users_db.get(username)
    if not stored_hash:
        return jsonify({"error": "Invalid username or password"}), 401

    if bcrypt.verify_password(password, stored_hash):
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401


if __name__ == '__main__':
    app.run()


