# Import necessary modules
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher as ph
from threading import Lock
import time

# Define a token bucket for rate limiting
class TokenBucket:
    def __init__(self, capacity, refill_rate):
        # Initialize token bucket parameters
        self.capacity, self.tokens = capacity, capacity
        self.last_refill_time, self.refill_rate = time.time(), refill_rate
        self.lock = Lock()

    def _refill(self):
        # Refill tokens based on elapsed time
        now, elapsed_time = time.time(), now - self.last_refill_time
        tokens_to_add = elapsed_time * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill_time = now

    def consume(self, tokens):
        # Consume tokens and check if there are enough tokens available
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

# Create a token bucket with a capacity of 10 and a refill rate of 1 token per second
rate_limiter = TokenBucket(capacity=10, refill_rate=1)

# Connect to SQLite database
connection = sqlite3.connect('totally_not_my_privateKeys.db', detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
cursor = connection.cursor()

# Define table creation queries
tables = [
    '''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''',
    '''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP DEFAULT NULL
    )
    ''',
    '''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    '''
]

# Create tables if they do not exist
for table in tables:
    cursor.execute(table)

# Server configuration
hostName, serverPort = "localhost", 8080

# Generate RSA private keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Define serialization formats
key_format = serialization.Encoding.PEM
private_bytes_format = serialization.PrivateFormat.TraditionalOpenSSL
encryption_algorithm = serialization.NoEncryption()

# Serialize private keys
pem = private_key.private_bytes(encoding=key_format, format=private_bytes_format, encryption_algorithm=encryption_algorithm)
expired_pem = expired_key.private_bytes(encoding=key_format, format=private_bytes_format, encryption_algorithm=encryption_algorithm)

# PKCS1 serialization format
pempkcs1_format = serialization.PrivateFormat.PKCS8

# Serialize private keys in PKCS1 format
pempkcs1 = private_key.private_bytes(encoding=key_format, format=pempkcs1_format, encryption_algorithm=encryption_algorithm)
expired_pempkcs1 = expired_key.private_bytes(encoding=key_format, format=pempkcs1_format, encryption_algorithm=encryption_algorithm)

# Insert keys into the database with expiration timestamps
cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (1, expired_pempkcs1, int(time.time())))
cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (2, pempkcs1, int(time.time() + 3600)))

# Extract public key numbers
numbers = private_key.private_numbers()

def int_to_base64(value):
    # Convert an integer to Base64URL-encoded string
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Custom server class derived from BaseHTTPRequestHandler
class MyServer(BaseHTTPRequestHandler):
    def _send_response(self, status):
        # Helper method to send HTTP response
        self.send_response(status)
        self.end_headers()

    def _handle_unsupported_methods(self):
        # Helper method to handle unsupported HTTP methods
        self._send_response(405)

    def do_PUT(self):
        self._handle_unsupported_methods()

    def do_PATCH(self):
        self._handle_unsupported_methods()

    def do_DELETE(self):
        self._handle_unsupported_methods()

    def do_HEAD(self):
        self._handle_unsupported_methods()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Rate limit requests to 10 requests per second
            if not rate_limiter.consume(1):
                self._send_response(429)  # Too Many Requests
                return

            headers = {"kid": "goodKID"}
            token_payload = {"user": "username", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            cursor.execute("SELECT key FROM keys WHERE kid = 2")
            row = cursor.fetchone()
            selected_pem = row[0]

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                cursor.execute("SELECT key FROM keys WHERE kid = 1")
                row = cursor.fetchone()
                selected_pem = row[0]

            # Deserialize selected_pem
            decoded_selected_pem = serialization.load_pem_private_key(selected_pem, password=None, backend=default_backend())

            # Generate JWT token
            encoded_jwt = jwt.encode(token_payload, decoded_selected_pem, algorithm="RS256", headers=headers)

            # Log the auth request
            self.log_auth_request(self.client_address[0], token_payload.get("user"))

            self._send_response(200)
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

        elif parsed_path.path == "/register":
            # Parse the request body to get the username and email
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))
            username, email = request_data.get('username'), request_data.get('email', None)

            # Check if the username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                self._send_response(400)  # Bad Request
                return

            # Generate a random UUID as the password
            password = str(uuid.uuid4())

            # Hash the password using argon2
            ph_instance = ph()
            password_hash = ph_instance.hash(password)

            # Insert the new user into the database, handling the case when email is not provided
            if email is not None:
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
            else:
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))

            # Retrieve the newly inserted user, coalescing NULL values in last_login
            cursor.execute("SELECT id, username, password_hash, email, date_registered, last_login FROM users WHERE username = ?", (username,))
            new_user = cursor.fetchone()

            connection.commit()

            # Return the password and last_login to the client
            last_login = new_user[5] if new_user[5] is not None else None
            response_data = {"password": password, "last_login": last_login}
            self._send_response(201)  # Created
            self.send_header("Content-type", "application/json")
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

        else:
            self._send_response(405)  # Method Not Allowed

    def log_auth_request(self, request_ip, username):
        # Log the auth request in the auth_logs table
        cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, (SELECT id FROM users WHERE username = ?))", (request_ip, username))
        connection.commit()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            # Handle GET request for JSON Web Keys endpoint
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
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
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
        else:
            self._send_response(405)  # Method Not Allowed

# Main block to run the server
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
