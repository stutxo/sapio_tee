"""Run only inside an isolated, network-disabled sandbox with loopback enabled."""

import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import web


spec = importlib.util.spec_from_file_location("install_web", Path(__file__).with_name("install-web.py"))
install_web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install_web)


def envelope():
    # Opaque byte payloads intentionally are not valid wallet/PSBT semantics:
    # those belong to the enclave and browser, never the transport adapter.
    return {"SignProgramV1": {
        "instance": {"evaluator": "00" * 31 + "02", "program": [1], "parameters": []},
        "input_index": 0, "witness": [], "path": "KeyPath", "psbt": [0, 0, 0, 1, 255],
    }}


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []
        self.response = b' { "RejectedV1" : "fixture rejection" } \n'
        self.upstream_mode = "normal"
        self.peers = set()

        async def oracle(reader, writer):
            self.peers.add(writer)
            try:
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                self.received.append(await reader.readexactly(size))
                if self.upstream_mode == "oversized":
                    writer.write(struct.pack(">I", web.MAX_MESSAGE + 1))
                elif self.upstream_mode == "truncated":
                    writer.write(struct.pack(">I", 20) + b"{}")
                elif self.upstream_mode == "silent":
                    await reader.read()
                    return
                else:
                    writer.write(struct.pack(">I", len(self.response)) + self.response)
                await writer.drain()
            finally:
                writer.close()
                self.peers.discard(writer)

        self.oracle = await asyncio.start_server(oracle, "127.0.0.1", 0)
        oracle_port = self.oracle.sockets[0].getsockname()[1]
        self.relay = web.Relay({"/": (b"public fixture", "text/html")}, "http://localhost:8123",
                               "127.0.0.1", oracle_port, True)
        self.server = await asyncio.start_server(self.relay.connection, "127.0.0.1", 0,
                                                 limit=web.MAX_HEADERS)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        self.oracle.close()
        await self.server.wait_closed()
        await self.oracle.wait_closed()
        for writer in tuple(self.peers):
            writer.close()

    async def request(self, body=None, method="POST", path="/api/sign", headers=None):
        if body is None:
            body = json.dumps(envelope()).encode()
        values = {"Host": "localhost:8123", "Origin": "http://localhost:8123",
                  "Content-Type": "application/json", "Content-Length": str(len(body))}
        if headers:
            for key, value in headers.items():
                if value is None:
                    values.pop(key, None)
                else:
                    values[key] = value
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            header = f"{method} {path} HTTP/1.1\r\n" + "".join(
                f"{key}: {value}\r\n" for key, value in values.items()) + "\r\n"
            writer.write(header.encode() + body)
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), 2)
            head, response = result.split(b"\r\n\r\n", 1)
            return int(head.split(b" ")[1]), response
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_exact_bytes_both_directions_and_one_connection(self):
        body = (" \n" + json.dumps(envelope(), indent=2) + "\t").encode()
        status, response = await self.request(body)
        self.assertEqual((status, response), (200, self.response))
        self.assertEqual(self.received, [body])

    async def test_wrong_origin_host_and_setup_never_reach_oracle(self):
        for headers in ({"Origin": "https://evil.invalid"}, {"Origin": None}, {"Host": "evil.invalid"}):
            with self.subTest(headers=headers):
                self.assertEqual((await self.request(headers=headers))[0], 403)
        self.assertEqual((await self.request(path="/setup"))[0], 404)
        self.assertEqual((await self.request(path="/public-key"))[0], 404)
        self.assertEqual(self.received, [])

    async def test_ambiguous_or_unsupported_payload_is_not_forwarded(self):
        malformed = [b'{"SignProgramV1":{},"SignProgramV1":{}}', b'{"Setup":{}}']
        request = envelope()
        request["SignProgramV1"]["psbt"][3] = 2
        malformed.append(json.dumps(request).encode())
        request = envelope()
        request["SignProgramV1"]["instance"]["program"] = [True]
        malformed.append(json.dumps(request).encode())
        for body in malformed:
            with self.subTest(body=body):
                self.assertEqual((await self.request(body))[0], 400)
        self.assertEqual((await self.request(headers={"Content-Length": "1000001"}))[0], 413)
        self.assertEqual((await self.request(headers={"Transfer-Encoding": "chunked"}))[0], 400)
        self.assertEqual(self.received, [])

    async def test_bad_upstream_frames_fail_without_retry(self):
        for mode in ("oversized", "truncated"):
            self.upstream_mode = mode
            with self.subTest(mode=mode):
                self.assertEqual((await self.request())[0], 502)
        self.assertEqual(len(self.received), 2)

    async def test_static_allowlist_does_not_serve_source_or_traversal(self):
        self.assertEqual(await self.request(b"", "GET", "/"), (200, b"public fixture"))
        for path in ("/../web.py", "/%2e%2e/web.py", "/key.pem", "/wallet-config.json?x=1", "/setup"):
            with self.subTest(path=path):
                self.assertEqual((await self.request(b"", "GET", path))[0], 404)
        self.assertEqual(self.received, [])

    async def test_admission_is_bounded_before_headers_arrive(self):
        clients = [await asyncio.open_connection("127.0.0.1", self.port)
                   for _ in range(web.MAX_CONNECTIONS)]
        try:
            rejected_reader, rejected_writer = await asyncio.open_connection("127.0.0.1", self.port)
            try:
                response = await asyncio.wait_for(rejected_reader.readuntil(b"\r\n\r\n"), 2)
                self.assertEqual(int(response.split(b" ")[1]), 503)
            finally:
                rejected_writer.close()
                await rejected_writer.wait_closed()
            self.assertEqual(self.received, [])
        finally:
            for _reader, writer in clients:
                writer.close()
                await writer.wait_closed()

    async def test_total_deadline_releases_silent_upstream_and_admission(self):
        self.upstream_mode = "silent"
        with patch.object(web, "TIMEOUT", 0.05):
            status, _body = await self.request()
            self.assertEqual(status, 504)
        self.upstream_mode = "normal"
        self.assertEqual((await self.request())[0], 200)
        self.assertEqual(len(self.received), 2)

    async def test_production_requires_proxy_https_even_with_matching_origin(self):
        self.relay.origin = "https://wallet.example.com"
        self.relay.host = "wallet.example.com"
        self.relay.allow_local_dev = False
        headers = {"Host": self.relay.host, "Origin": self.relay.origin}
        self.assertEqual((await self.request(headers=headers))[0], 403)
        self.assertEqual(self.received, [])
        headers["X-Forwarded-Proto"] = "https"
        self.assertEqual((await self.request(headers=headers))[0], 200)


class InstallerTests(unittest.TestCase):
    def identity(self):
        # A synthetic public generator point; no private keys or live identity.
        raw = bytes.fromhex("043587cf") + bytes(9) + bytes([1]) * 32 + bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        checked = raw + hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
        number, xpub = int.from_bytes(checked, "big"), ""
        while number:
            number, digit = divmod(number, 58)
            xpub = install_web.BASE58[digit] + xpub
        return {"protocol": "sapio-tee/program-oracle/1", "mode": "local-dev", "xpub": xpub,
                "settings": None, "signing": {
                    "protocol": "SignProgramV1", "max_connections": 4, "request_timeout_secs": 30,
                    "inline_evaluators": [{"id": "00" * 32, "wasm_version": 1},
                                          {"id": "00" * 31 + "02", "wasm_version": 2}],
                    "registered_evaluators": [{"name": "pay-at-least/v1", "id": "ab" * 32,
                                               "wasm_version": 1}],
                }}

    def test_staging_is_repeatable_public_only_and_pins_verified_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "assets"
            source.mkdir()
            for name in web.ASSETS:
                if name != "wallet-config.json":
                    (source / name).write_bytes(b"\x00asm\x01\x00\x00\x00" if name.endswith(".wasm") else b"fixture")
            identity = self.identity()
            data = json.dumps(identity).encode()
            identity_path = root / "verified.json"
            identity_path.write_bytes(data)
            staged = root / "stage"
            arguments = ["install-web.py", "--hostname", "localhost", "--port", "8123",
                         "--assets", str(source), "--identity", str(identity_path),
                         "--identity-sha256", hashlib.sha256(data).hexdigest(),
                         "--stage-dir", str(staged), "--allow-local-dev"]
            with patch.object(sys, "argv", arguments), patch.object(
                    install_web, "command", side_effect=AssertionError("staging ran a host command")):
                install_web.main()
                config_path = staged / "opt/sapio-wallet/static/wallet-config.json"
                first = config_path.read_bytes()
                install_web.main()
                self.assertEqual(config_path.read_bytes(), first)
                self.assertEqual(json.loads(first), {"version": 1, "identity": identity,
                                                     "sign_url": "./api/sign", "allow_local_dev": True})
                self.assertFalse((staged / "etc/sapio-wallet/tls/key.pem").exists())
                identity_path.write_bytes(data + b" ")
                with self.assertRaises(SystemExit) as failure:
                    install_web.main()
                self.assertEqual(failure.exception.code, 1)
                self.assertEqual(config_path.read_bytes(), first)

    def test_public_identity_cannot_smuggle_private_or_wrong_network_key(self):
        data = self.identity()
        install_web.validate_identity(json.dumps(data).encode(), True)
        data["mode"] = "nitro"
        data["settings"] = {"network": "bitcoin", "blockhash": "01" * 32, "key_id": "fixture-public-key-id"}
        with self.assertRaises(ValueError):
            install_web.validate_identity(json.dumps(data).encode(), False)
        data["xpub"] = "xprv" + "1" * 107
        with self.assertRaises(ValueError):
            install_web.validate_identity(json.dumps(data).encode(), False)


if __name__ == "__main__":
    unittest.main()
