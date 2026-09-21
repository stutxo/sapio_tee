#!/usr/bin/env python3
"""Initialize a Nitro signer and wait for a matching, healthy public identity.

This is an operational readiness check, not cryptographic attestation.
"""

import argparse
import http.client
import json
import math
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_RESPONSE = 65536


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def json_value(data):
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def validate_settings(settings):
    require(isinstance(settings, dict) and set(settings) == {"key_id", "blockhash", "network"},
            "settings must contain exactly key_id, blockhash and network")
    require(all(isinstance(value, str) and value for value in settings.values()),
            "all settings must be nonempty strings")
    blockhash = settings["blockhash"]
    require(len(blockhash) == 64 and all(char in "0123456789abcdef" for char in blockhash)
            and int(blockhash, 16) != 0, "blockhash must be canonical nonzero lowercase 64-hex")
    # The API remains authoritative for its measured region/key/network allowlist.
    # In particular, an HTTP 400 is fatal rather than a startup retry.


def validate_identity(body, settings):
    identity = json_value(body)
    require(isinstance(identity, dict) and set(identity) == {
        "protocol", "mode", "xpub", "settings", "signing",
    }, "unexpected public identity fields")
    require(identity["protocol"] == "sapio-tee/program-oracle/1",
            "unsupported identity protocol")
    require(identity["mode"] == "nitro", "identity is not a Nitro signer (local-dev is forbidden)")
    require(identity["settings"] == settings, "initialized identity settings mismatch; refusing to reconfigure")
    require(isinstance(identity["xpub"], str) and identity["xpub"].strip(), "missing xpub")
    require(isinstance(identity["signing"], dict), "missing signing profile")
    return identity


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class DeadlineExpired(Exception):
    pass


def initialize(settings, url, timeout):
    deadline = time.monotonic() + timeout
    # Do not send public setup inputs through ambient proxies or follow redirects.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    payload = json.dumps(settings).encode("utf-8")
    last_status = "service has not responded"

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise DeadlineExpired()
        return seconds

    def request(path, data=None):
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url + path, data=data, headers=headers)
        try:
            # The enclave's KMS setup operation itself may take up to 45 seconds.
            response = opener.open(req, timeout=min(60.0, remaining()))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(MAX_RESPONSE + 1)
            require(len(body) <= MAX_RESPONSE, f"{path} response exceeds 64 KiB")
            remaining()
            return response.code, body

    def unexpected(path, status, body):
        detail = body[:512].decode("utf-8", errors="replace")
        raise ValueError(f"{path} returned HTTP {status}: {detail}")

    # Socket timeouts alone do not bound DNS resolution or a trickling response.
    # This CLI runs on the Linux parent and a process-wide timer bounds those too.
    def alarm(signum, frame):
        raise DeadlineExpired()

    previous_handler = signal.signal(signal.SIGALRM, alarm)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining())
        while True:
            remaining()
            try:
                status, body = request("/public-key")
                identity = None
                if status == 200:
                    identity = validate_identity(body, settings)
                elif status == 503:
                    status, body = request("/setup", payload)
                    if status == 200:
                        identity = validate_identity(body, settings)
                    elif status in (409, 502):
                        last_status = f"/setup returned HTTP {status}"
                    else:
                        unexpected("/setup", status, body)
                else:
                    unexpected("/public-key", status, body)
                if identity is not None:
                    status, body = request("/health")
                    if status == 200:
                        return identity
                    if status != 503:
                        unexpected("/health", status, body)
                    last_status = "/health is not ready (HTTP 503)"
            except urllib.error.URLError as error:
                if isinstance(error.reason, ssl.SSLError):
                    raise ValueError(f"TLS failure: {error.reason}") from error
                if not isinstance(error.reason, (ConnectionError, TimeoutError, socket.gaierror)):
                    raise ValueError(f"HTTP connection failed: {error.reason}") from error
                last_status = f"waiting for connection: {error.reason}"
            except (ConnectionError, TimeoutError) as error:
                last_status = f"waiting for connection: {error}"
            time.sleep(min(1.0, remaining()))
    except DeadlineExpired:
        raise ValueError(f"timed out after {timeout:g} seconds: {last_status}") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True, help="public setup JSON file")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="HTTP API base URL")
    parser.add_argument("--timeout", type=float, default=120, help="overall deadline in seconds (default 120)")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    try:
        url = urllib.parse.urlsplit(args.url)
        require(url.scheme in ("http", "https") and url.hostname and url.port != 0
                and url.username is None and url.password is None
                and not url.query and not url.fragment and url.path in ("", "/"),
                "--url must be an HTTP(S) origin without credentials, path, query or fragment")
        with open(args.settings, "rb") as source:
            data = source.read(MAX_RESPONSE + 1)
        require(len(data) <= MAX_RESPONSE, "settings exceed 64 KiB")
        settings = json_value(data)
        validate_settings(settings)
        identity = initialize(settings, args.url.rstrip("/"), args.timeout)
        print(json.dumps(identity, separators=(",", ":")))
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(1, f"initialization failed: {error}\n")


if __name__ == "__main__":
    main()
