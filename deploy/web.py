#!/usr/bin/env python3
"""Bounded static-file and ProgramOracle transport; no wallet or signing logic.

Production listens only on loopback behind the installer's HTTPS nginx server.
The only upstream operation is one exact length-prefixed SignProgramV1 exchange.
"""

import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from urllib.parse import urlsplit


MAX_MESSAGE = 1_000_000
MAX_HEADERS = 16_384
MAX_ASSET = 16 * 1024 * 1024
MAX_CONNECTIONS = 4
TIMEOUT = 30
ASSETS = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "wallet.js": "text/javascript; charset=utf-8",
    "wallet.wasm": "application/wasm",
    "recovery.js": "text/javascript; charset=utf-8",
    "recovery.wasm": "application/wasm",
    "passkey.wasm": "application/wasm",
    "wallet-config.json": "application/json",
}
SECURITY_HEADERS = (
    "Cache-Control: no-store\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Cross-Origin-Opener-Policy: same-origin\r\n"
    "Cross-Origin-Resource-Policy: same-origin\r\n"
    "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n"
    "Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; "
    "style-src 'self'; connect-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n"
)
STATUS = {
    200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 411: "Length Required", 413: "Content Too Large",
    415: "Unsupported Media Type", 431: "Request Header Fields Too Large",
    502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
}


class HTTPError(Exception):
    def __init__(self, status):
        self.status = status


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def invalid_constant(_value):
    raise ValueError("non-finite JSON value")


def json_value(data):
    # Decode explicitly: JSON over this wire is UTF-8, not Python's auto-detected
    # UTF-16/32 extension. Duplicate keys must not be interpreted differently.
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON encoding or nesting") from error


def byte_array(value, maximum):
    return (isinstance(value, list) and len(value) <= maximum
            and all(type(item) is int and 0 <= item <= 255 for item in value))


def framed_psbt(value):
    # This checks only the wire's internal frame, not any wallet/PSBT semantics.
    return (byte_array(value, MAX_MESSAGE) and len(value) > 4
            and int.from_bytes(bytes(value[:4]), "big") == len(value) - 4)


def validate_request(data):
    value = json_value(data)
    require(isinstance(value, dict) and set(value) == {"SignProgramV1"},
            "unsupported oracle envelope")
    request = value["SignProgramV1"]
    require(isinstance(request, dict) and set(request) == {
        "instance", "input_index", "witness", "path", "psbt",
    }, "unsupported signing request")
    instance = request["instance"]
    require(isinstance(instance, dict) and set(instance) == {
        "evaluator", "program", "parameters",
    }, "unsupported instance envelope")
    require(isinstance(instance["evaluator"], str)
            and re.fullmatch(r"[0-9a-f]{64}", instance["evaluator"]) is not None,
            "invalid evaluator identifier")
    require(byte_array(instance["program"], 65_536)
            and byte_array(instance["parameters"], 65_536), "invalid instance bytes")
    require(type(request["input_index"]) is int and 0 <= request["input_index"] <= 0xFFFFFFFF,
            "invalid input index")
    require(byte_array(request["witness"], 65_536), "invalid witness bytes")
    require(request["path"] == "KeyPath", "unsupported spend path")
    require(framed_psbt(request["psbt"]), "invalid PSBT wire frame")


def validate_response(data):
    value = json_value(data)
    require(isinstance(value, dict) and len(value) == 1, "invalid oracle response")
    if "SignedV1" in value:
        require(framed_psbt(value["SignedV1"]), "invalid signed wire frame")
    else:
        require(set(value) == {"RejectedV1"} and isinstance(value["RejectedV1"], str),
                "unsupported oracle response")


def validate_origin(origin, allow_local_dev):
    parsed = urlsplit(origin)
    require(parsed.hostname is not None and parsed.username is None
            and parsed.password is None and not parsed.path and not parsed.query
            and not parsed.fragment, "origin must contain only scheme and authority")
    require(origin == origin.lower() and parsed.port != 0, "origin must be canonical")
    require(not any(character.isspace() for character in origin), "invalid origin")
    if allow_local_dev:
        require(parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"),
                "development requires an explicit HTTP loopback origin")
    else:
        require(parsed.scheme == "https", "production requires an HTTPS origin")
        require(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                             r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", parsed.hostname)
                and not parsed.hostname.endswith(".localhost"),
                "production requires a DNS hostname")
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise ValueError("production requires a DNS hostname, not an IP")
    expected_authority = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    default_port = 80 if allow_local_dev else 443
    if parsed.port is not None:
        require(parsed.port != default_port, "omit the default origin port")
        expected_authority += f":{parsed.port}"
    require(parsed.netloc == expected_authority, "origin authority must be canonical")
    return parsed.netloc


def regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                f"expected a nonempty bounded regular file: {Path(path).name}")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size, f"file changed while reading: {Path(path).name}")
        return data


def load_assets(directory, allow_local_dev):
    assets = {"/" + name: (regular_bytes(directory / name, MAX_ASSET), mime)
              for name, mime in ASSETS.items()}
    config = json_value(assets["/wallet-config.json"][0])
    require(isinstance(config, dict) and set(config) == {
        "version", "identity", "sign_url", "allow_local_dev",
    } and type(config["version"]) is int and config["version"] == 1
            and isinstance(config["identity"], dict) and config["sign_url"] == "./api/sign"
            and type(config["allow_local_dev"]) is bool
            and config["allow_local_dev"] == allow_local_dev, "invalid static wallet config")
    assets["/"] = assets["/index.html"]
    return assets


async def oracle_exchange(body, host, port):
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    reader, writer = await asyncio.open_connection(host, port, family=family)
    try:
        writer.write(struct.pack(">I", len(body)))
        writer.write(body)
        await writer.drain()
        size = struct.unpack(">I", await reader.readexactly(4))[0]
        require(0 < size <= MAX_MESSAGE, "invalid oracle frame size")
        response = await reader.readexactly(size)
        validate_response(response)
        return response
    finally:
        # The oracle supports multiple exchanges per socket; this adapter never
        # reuses it, retries, or waits for another response/frame.
        writer.close()


class Relay:
    def __init__(self, assets, origin, upstream_host, upstream_port, allow_local_dev=False):
        self.assets = assets
        self.origin = origin
        self.host = validate_origin(origin, allow_local_dev)
        self.upstream_host = str(ipaddress.ip_address(upstream_host))
        require(1 <= upstream_port <= 65535, "invalid upstream port")
        self.upstream_port = upstream_port
        self.allow_local_dev = allow_local_dev
        self.active = 0

    @staticmethod
    async def respond(writer, status, body=None, content_type="application/json"):
        if body is None:
            body = json.dumps({"error": STATUS[status]}, separators=(",", ":")).encode()
        header = (f"HTTP/1.1 {status} {STATUS[status]}\r\n"
                  f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
                  "Connection: close\r\n" + SECURITY_HEADERS + "\r\n")
        writer.write(header.encode("ascii"))
        writer.write(body)
        await writer.drain()

    async def request(self, reader, writer):
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError as error:
            raise HTTPError(431) from error
        if len(raw) > MAX_HEADERS:
            raise HTTPError(431)
        try:
            lines = raw[:-4].decode("ascii").split("\r\n")
            method, path, version = lines[0].split(" ")
            require(version == "HTTP/1.1" and path.startswith("/"), "invalid request line")
            headers = {}
            for line in lines[1:]:
                key, value = line.split(":", 1)
                require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key), "invalid header")
                require(all(32 <= ord(char) < 127 or char == "\t" for char in value),
                        "invalid header value")
                key = key.lower()
                require(key not in headers, "duplicate HTTP header")
                headers[key] = value.strip(" \t")
        except ValueError as error:
            raise HTTPError(400) from error
        if headers.get("host") != self.host:
            raise HTTPError(403)
        if headers.get("origin", self.origin) != self.origin:
            raise HTTPError(403)
        if not self.allow_local_dev and headers.get("x-forwarded-proto") != "https":
            raise HTTPError(403)
        if any(key in headers for key in ("transfer-encoding", "content-encoding", "expect", "upgrade")):
            raise HTTPError(400)
        if method == "GET":
            if headers.get("content-length", "0") != "0":
                raise HTTPError(400)
            if path == "/health":
                await self.respond(writer, 200, b'{"status":"ok"}')
            elif path in self.assets:
                body, mime = self.assets[path]
                await self.respond(writer, 200, body, mime)
            else:
                raise HTTPError(404)
            return
        if method != "POST":
            raise HTTPError(405)
        if path != "/api/sign":
            raise HTTPError(404)
        if headers.get("origin") != self.origin:
            raise HTTPError(403)
        if headers.get("content-type", "").lower() not in (
                "application/json", "application/json; charset=utf-8"):
            raise HTTPError(415)
        if "content-length" not in headers:
            raise HTTPError(411)
        length = headers["content-length"]
        if re.fullmatch(r"[1-9][0-9]{0,6}", length) is None:
            raise HTTPError(413 if length.isdigit() and len(length) > 6 else 400)
        size = int(length)
        if size > MAX_MESSAGE:
            raise HTTPError(413)
        body = await reader.readexactly(size)
        try:
            validate_request(body)
        except ValueError as error:
            raise HTTPError(400) from error
        try:
            response = await oracle_exchange(body, self.upstream_host, self.upstream_port)
        except (OSError, ValueError, asyncio.IncompleteReadError) as error:
            raise HTTPError(502) from error
        await self.respond(writer, 200, response)

    async def connection(self, reader, writer):
        if self.active >= MAX_CONNECTIONS:
            # No admission queue and no task waiting for a slot. This bounded
            # write is immediately closed, even when the client is not reading.
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
            writer.close()
            return
        self.active += 1
        deadline = asyncio.get_running_loop().time() + TIMEOUT
        try:
            try:
                # One wall-clock deadline includes headers, upload, upstream
                # connect/write/read, and the client response (not per-chunk).
                await asyncio.wait_for(self.request(reader, writer), TIMEOUT)
            except asyncio.TimeoutError:
                writer.write(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
            except HTTPError as error:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining > 0:
                    await asyncio.wait_for(self.respond(writer, error.status), remaining)
            except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
                # Truncated requests are never forwarded. Do not log body data.
                pass
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            remaining = deadline - asyncio.get_running_loop().time()
            try:
                if remaining > 0:
                    await asyncio.wait_for(writer.wait_closed(), remaining)
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                # Closing may otherwise retain a write buffer and socket after
                # releasing admission when a peer stops reading.
                writer.transport.abort()
                self.active -= 1


async def serve(args):
    address = ipaddress.ip_address(args.listen)
    require(address.is_loopback, "the relay must listen on loopback behind nginx")
    require(1 <= args.port <= 65535, "invalid listening port")
    relay = Relay(load_assets(args.assets, args.allow_local_dev), args.origin,
                  args.upstream_host, args.upstream_port, args.allow_local_dev)
    server = await asyncio.start_server(relay.connection, str(address), args.port,
                                        limit=MAX_HEADERS, backlog=MAX_CONNECTIONS)
    print(f"wallet transport ready on {address}:{args.port} for {args.origin}", flush=True)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--origin", required=True, help="exact public HTTPS origin, without trailing slash")
    parser.add_argument("--listen", default="127.0.0.1", help="numeric loopback address only")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--upstream-host", default="127.0.0.1", help="fixed numeric ProgramOracle IP")
    parser.add_argument("--upstream-port", type=int, default=8367)
    parser.add_argument("--allow-local-dev", action="store_true",
                        help="explicit isolated localhost HTTP fixture mode; never production")
    args = parser.parse_args()
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as error:
        parser.exit(1, f"wallet transport failed: {error}\n")


if __name__ == "__main__":
    main()
