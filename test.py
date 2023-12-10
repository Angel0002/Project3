import unittest
import threading
import requests
import datetime
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from main import MyServer

class TestMyServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a test HTTP server for testing
        cls.server = HTTPServer(("localhost", 8080), MyServer)

        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        # Shutdown the server
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_well_known_jwks(self):
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        keys = jwks["keys"]
        self.assertEqual(len(keys), 1)
        key = keys[0]
        self.assertEqual(key["alg"], "RS256")
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["kid"], "goodKID")

    @patch('main.datetime')
    def test_generate_jwt_token(self, mock_datetime):
        # Mock the current time to generate a token that's not expired
        mock_datetime.utcnow.return_value = datetime.datetime(2023, 10, 26)
        response = requests.post("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token)
        payload = json.loads(jwt.decode(token, verify=False))
        self.assertEqual(payload["user"], "username")

        # Mock the current time to generate a token that's expired
        mock_datetime.utcnow.return_value = datetime.datetime(2023, 10, 25)
        response = requests.post("http://localhost:8080/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token)
        payload = json.loads(jwt.decode(token, verify=False))
        self.assertEqual(payload["user"], "username")

if __name__ == '__project3__':
    unittest.main()
