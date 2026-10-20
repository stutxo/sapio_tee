"""Regression coverage for the deploy initializer's retryable setup statuses."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("initialize", ROOT / "deploy/initialize.py")
INITIALIZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INITIALIZE)

SETTINGS = {
    "key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "blockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "network": "regtest",
}
IDENTITY = {
    "protocol": "sapio-tee/program-oracle/1",
    "mode": "nitro",
    "xpub": "xpub-fixture",
    "settings": SETTINGS,
    "signing": {},
}


class FixtureHandler(BaseHTTPRequestHandler):
    public_calls = 0
    setup_calls = 0

    def send_json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/public-key":
            type(self).public_calls += 1
            if type(self).setup_calls < 2:
                self.send_json(503, {"error": "not initialized"})
            else:
                self.send_json(200, IDENTITY)
        elif self.path == "/health":
            self.send_json(200, {"status": "ready"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/setup":
            type(self).setup_calls += 1
            if type(self).setup_calls == 1:
                self.send_json(408, {"error": "request deadline exceeded"})
            else:
                self.send_json(200, IDENTITY)
        else:
            self.send_json(404, {"error": "not found"})

    def log_message(self, format, *args):
        pass


class InitializerRetries(unittest.TestCase):
    def test_setup_408_is_retried(self):
        FixtureHandler.public_calls = 0
        FixtureHandler.setup_calls = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            identity = INITIALIZE.initialize(SETTINGS, url, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(identity, IDENTITY)
        self.assertGreaterEqual(FixtureHandler.setup_calls, 2)


if __name__ == "__main__":
    unittest.main()
