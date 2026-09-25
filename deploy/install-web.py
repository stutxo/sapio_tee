#!/usr/bin/env python3
"""Install a static wallet and HTTPS transport on the existing AL2023 parent.

No enclave, KMS, setup API, Terraform, root key or EIF changes are performed.
The identity must already have passed independent attestation verification;
--identity-sha256 pins those exact verified file bytes, not a fetched identity.
Staging writes only a deployment tree (never a TLS private key), without dnf,
systemctl, nginx execution or network access. Local HTTP requires both explicit
--allow-local-dev and --stage-dir and is exclusively for isolated fixtures.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from web import ASSETS, MAX_ASSET, json_value, regular_bytes, require, validate_origin


APP = Path("/opt/sapio-wallet")
TLS = Path("/etc/sapio-wallet/tls")
SERVICE = Path("/etc/systemd/system/sapio-wallet.service")
NGINX = Path("/etc/nginx/conf.d/sapio-wallet.conf")
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def public_xpub(value, network):
    require(isinstance(value, str) and 100 <= len(value) <= 120, "invalid public xpub")
    number = 0
    for char in value:
        require(char in BASE58, "invalid xpub encoding")
        number = number * 58 + BASE58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(value) - len(value.lstrip("1"))) + raw
    require(len(raw) == 82 and hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
            == raw[-4:], "invalid xpub checksum")
    version = b"\x04\x88\xb2\x1e" if network == "bitcoin" else b"\x04\x35\x87\xcf"
    require(raw[:4] == version and raw[4] <= 245, "xpub network or derivation depth mismatch")
    require(raw[4] != 0 or raw[5:13] == bytes(8), "invalid depth-zero xpub")
    require(raw[45] in (2, 3), "identity must contain a public, not private, BIP32 key")
    field = 2**256 - 2**32 - 977
    x = int.from_bytes(raw[46:78], "big")
    require(x < field and pow((x*x*x + 7) % field, (field - 1) // 2, field) == 1,
            "invalid compressed xpub point")


def validate_identity(data, allow_local_dev):
    identity = json_value(data)
    require(isinstance(identity, dict) and set(identity) == {
        "protocol", "mode", "xpub", "settings", "signing",
    }, "unexpected public identity fields")
    require(identity["protocol"] == "sapio-tee/program-oracle/1", "unsupported identity protocol")
    if identity["mode"] == "local-dev":
        require(allow_local_dev and identity["settings"] is None,
                "unattested identity requires explicit isolated local development")
        network = "regtest"
    else:
        require(identity["mode"] == "nitro", "expected a verified Nitro identity")
        settings = identity["settings"]
        require(isinstance(settings, dict) and set(settings) == {"key_id", "blockhash", "network"},
                "invalid identity settings")
        require(all(isinstance(item, str) and item for item in settings.values()),
                "invalid identity settings values")
        require(re.fullmatch(r"[0-9a-f]{64}", settings["blockhash"])
                and int(settings["blockhash"], 16) != 0, "invalid pinned blockhash")
        network = settings["network"]
        require(network in ("bitcoin", "testnet", "testnet4", "signet", "regtest"),
                "unsupported identity network")
    public_xpub(identity["xpub"], network)
    signing = identity["signing"]
    require(isinstance(signing, dict) and set(signing) == {
        "protocol", "inline_evaluators", "registered_evaluators", "max_connections", "request_timeout_secs",
    }, "invalid signing profile")
    require(signing["protocol"] == "SignProgramV1"
            and type(signing["max_connections"]) is int and signing["max_connections"] == 4
            and type(signing["request_timeout_secs"]) is int and signing["request_timeout_secs"] == 30,
            "unexpected measured transport profile")
    require(signing["inline_evaluators"] == [
        {"id": "00" * 32, "wasm_version": 1},
        {"id": "00" * 31 + "02", "wasm_version": 2},
    ], "identity does not advertise the expected inline WASM v1/v2 evaluators")
    registered = signing["registered_evaluators"]
    require(isinstance(registered, list) and len(registered) == 1,
            "unexpected registered evaluator profile")
    entry = registered[0]
    require(isinstance(entry, dict) and set(entry) == {"name", "id", "wasm_version"}
            and entry["name"] == "pay-at-least/v1" and type(entry["wasm_version"]) is int
            and entry["wasm_version"] == 1 and isinstance(entry["id"], str)
            and re.fullmatch(r"[0-9a-f]{64}", entry["id"]), "invalid registered evaluator")
    # Its exact registered-module digest, KMS key, measurements and blockchain
    # settings are the independent verifier's responsibility, not this installer.
    return identity


def validate_tls(cert, key, hostname):
    # Validate key matching, hostname, certificate dates and full public trust
    # chain using a real TLS handshake over memory BIOs. No DNS/network, openssl
    # subprocess, key printing, password prompt or self-signed fallback.
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(str(cert), str(key), password=lambda: b"")
    client = ssl.create_default_context()
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_tls = client.wrap_bio(client_in, client_out, server_hostname=hostname)
    server_tls = server.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        if not client_done:
            try:
                client_tls.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        server_in.write(client_out.read())
        if not server_done:
            try:
                server_tls.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        client_in.write(server_out.read())
        if client_done and server_done:
            return
    raise ValueError("TLS certificate validation did not complete")


def nginx_config(hostname, port, relay_port, allow_local_dev):
    if allow_local_dev:
        address = "[::1]" if hostname == "::1" else "127.0.0.1"
        listen = f"listen {address}:{port};"
        tls = ""
    else:
        listen = f"listen {port} ssl;\n    listen [::]:{port} ssl;"
        tls = f"""
    ssl_certificate {TLS}/fullchain.pem;
    ssl_certificate_key {TLS}/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    add_header Strict-Transport-Security \"max-age=31536000\" always;"""
    proxy = f"proxy_pass http://127.0.0.1:{relay_port};"
    static_names = "|".join(re.escape(name) for name in ASSETS)
    return f"""# Managed by install-web.py; no enclave or port-8000 routes.
server {{
    {listen}
    server_name {hostname};{tls}
    access_log off;
    client_max_body_size 1000000;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 5s;
    large_client_header_buffers 2 8k;
    if ($host != {hostname}) {{ return 421; }}
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Origin $http_origin;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Connection close;
    proxy_set_header Accept-Encoding \"\";
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_connect_timeout 3s;
    proxy_send_timeout 30s;
    proxy_read_timeout 31s;
    proxy_next_upstream off;
    location = /api/sign {{
        limit_except POST {{ deny all; }}
        {proxy}
    }}
    location = /health {{
        limit_except GET {{ deny all; }}
        {proxy}
    }}
    location = / {{
        limit_except GET {{ deny all; }}
        {proxy}
    }}
    location ~ ^/(?:{static_names})$ {{
        limit_except GET {{ deny all; }}
        {proxy}
    }}
    location / {{ return 404; }}
}}
"""


def service_config(origin, relay_port, upstream_host, upstream_port, allow_local_dev):
    development = " --allow-local-dev" if allow_local_dev else ""
    return f"""[Unit]
Description=Sapio static wallet and bounded ProgramOracle transport
After=network.target

[Service]
Type=exec
DynamicUser=yes
ExecStart=/usr/bin/python3 -I {APP}/web.py --assets {APP}/static --origin {origin} --port {relay_port} --upstream-host {upstream_host} --upstream-port {upstream_port}{development}
Restart=on-failure
RestartSec=3
TimeoutStopSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
InaccessiblePaths=-/etc/sapio-wallet -/opt/sapio-tee
ReadOnlyPaths={APP}
MemoryMax=192M
TasksMax=16
LimitNOFILE=64
CPUQuota=100%

[Install]
WantedBy=multi-user.target
"""


def safe_directory(path, mode=0o755):
    # Do not follow an operator/staging-tree symlink while installing as root.
    if path == path.parent:
        return
    safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        require(not path.is_symlink() and path.is_dir(), f"unsafe installation directory: {path}")
    else:
        path.mkdir(mode=mode)


def install_file(path, data, mode=0o644):
    safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        require(not path.is_symlink() and path.is_file(), f"unsafe installation file: {path}")
        info = path.stat()
        require(info.st_nlink == 1, f"hard-linked installation file: {path}")
        if info.st_size == len(data) and path.read_bytes() == data:
            path.chmod(mode)
            return
    descriptor, temporary = tempfile.mkstemp(prefix=".wallet-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(*arguments):
    # Never pass private key bytes or uncontrolled shell fragments to a process.
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=180, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
    if result.returncode:
        # Tool diagnostics can contain paths but cannot contain key bytes: nginx
        # reads keys directly and its output is deliberately not copied here.
        raise ValueError(f"{arguments[0]} {arguments[1]} failed (exit {result.returncode}); "
                         "inspect the host service/configuration diagnostics")


def check_platform():
    require(os.geteuid() == 0, "production installation requires root")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    require(release.get("ID") == "amzn" and release.get("VERSION_ID") == "2023",
            "production installation supports Amazon Linux 2023 only")
    require(Path("/usr/bin/python3").is_file(), "system Python 3 is required")


def https_get(hostname, port, authority, path):
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(hostname, port, timeout=3, context=context)
    # Readiness verifies the local nginx with the real SNI/Host and public trust
    # chain, independent of DNS propagation and ambient HTTP proxy variables.
    connection.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3),
                                          server_hostname=hostname)
    try:
        connection.request("GET", path, headers={"Host": authority, "Connection": "close"})
        response = connection.getresponse()
        data = response.read(65_537)
        require(response.status == 200 and len(data) <= 65_536,
                "HTTPS readiness returned an unexpected response")
        return data
    finally:
        connection.close()


def ready(args, authority, config):
    deadline = time.monotonic() + 20
    while True:
        try:
            require(json_value(https_get(args.hostname, args.port, authority, "/health"))
                    == {"status": "ok"}, "relay is not healthy")
            require(json_value(https_get(args.hostname, args.port, authority, "/wallet-config.json"))
                    == config, "served identity/config does not match the verified input")
            with socket.create_connection((args.upstream_host, args.upstream_port), timeout=3):
                pass
            return
        except (OSError, ValueError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise ValueError("readiness failed: check local HTTPS, pinned config and ProgramOracle TCP; "
                                 "the installer does not initialize or reconfigure the enclave") from None
            time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hostname", required=True, help="stable public DNS name (no scheme/path)")
    parser.add_argument("--assets", required=True, type=Path, help="prebuilt static wallet directory")
    parser.add_argument("--identity", required=True, type=Path, help="independently verified public identity JSON")
    parser.add_argument("--identity-sha256", required=True,
                        help="SHA256 of the exact identity file accepted by the independent verifier")
    parser.add_argument("--tls-cert", type=Path, help="PEM full chain, leaf first, trusted by system public CAs")
    parser.add_argument("--tls-key", type=Path, help="matching unencrypted PEM private key; never logged")
    parser.add_argument("--port", type=int, help="external port (default 443; development default 8000)")
    parser.add_argument("--relay-port", type=int, default=8081)
    parser.add_argument("--upstream-host", default="127.0.0.1", help="fixed numeric ProgramOracle address")
    parser.add_argument("--upstream-port", type=int, default=8367)
    parser.add_argument("--stage-dir", type=Path, help="generate a deployment tree only; never copy TLS private keys")
    parser.add_argument("--allow-local-dev", action="store_true",
                        help="HTTP loopback fixtures only, requires --stage-dir; never installed on the host")
    args = parser.parse_args()
    try:
        require(not args.allow_local_dev or args.stage_dir is not None,
                "local development is allowed only with --stage-dir")
        if args.port is None:
            args.port = 8000 if args.allow_local_dev else 443
        require(all(1 <= number <= 65535 for number in (args.port, args.relay_port, args.upstream_port)),
                "ports must be in 1..65535")
        args.upstream_host = str(ipaddress.ip_address(args.upstream_host))
        scheme = "http" if args.allow_local_dev else "https"
        host = f"[{args.hostname}]" if args.hostname == "::1" else args.hostname
        default_port = 80 if args.allow_local_dev else 443
        authority = host + (f":{args.port}" if args.port != default_port else "")
        origin = f"{scheme}://{authority}"
        validate_origin(origin, args.allow_local_dev)
        require(args.hostname == origin.split("://", 1)[1].split(":", 1)[0]
                or args.hostname == "::1" and args.allow_local_dev,
                "--hostname must be a bare canonical hostname, without port or URL syntax")
        identity_data = regular_bytes(args.identity, 65_536)
        require(re.fullmatch(r"[0-9a-f]{64}", args.identity_sha256)
                and hashlib.sha256(identity_data).hexdigest() == args.identity_sha256,
                "verified identity file SHA256 does not match")
        identity = validate_identity(identity_data, args.allow_local_dev)
        assets = {name: regular_bytes(args.assets / name, MAX_ASSET)
                  for name in ASSETS if name != "wallet-config.json"}
        for name in ("wallet.wasm", "recovery.wasm", "passkey.wasm"):
            require(assets[name].startswith(b"\x00asm\x01\x00\x00\x00"), f"invalid built WASM artifact: {name}")
        config = {"version": 1, "identity": identity, "sign_url": "./api/sign",
                  "allow_local_dev": args.allow_local_dev}
        config_bytes = (json.dumps(config, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        cert_data = key_data = None
        if args.allow_local_dev:
            require(args.tls_cert is None and args.tls_key is None, "development mode does not use TLS files")
        else:
            require(args.tls_cert is not None and args.tls_key is not None,
                    "production requires --tls-cert and --tls-key; there is no HTTP fallback")
            cert_data = regular_bytes(args.tls_cert, 262_144)
            key_data = regular_bytes(args.tls_key, 65_536)
            # Validate the exact bytes that will be installed, not a second read
            # of potentially changed operator files. The temporary private key
            # is 0600 in a 0700 directory and is removed even on validation error.
            with tempfile.TemporaryDirectory(prefix="sapio-wallet-tls-") as temporary:
                certificate = Path(temporary) / "certificate.pem"
                private_key = Path(temporary) / "key.pem"
                install_file(certificate, cert_data, 0o600)
                install_file(private_key, key_data, 0o600)
                validate_tls(certificate, private_key, args.hostname)
        if args.stage_dir is None:
            check_platform()
            require(args.port not in (args.relay_port, args.upstream_port, 8000),
                    "HTTPS port must not collide with the relay or enclave API/oracle")
            require(args.relay_port not in (args.upstream_port, 8000),
                    "relay port must not collide with the enclave API/oracle")
            if shutil.which("nginx") is None:
                command("/usr/bin/dnf", "install", "-y", "nginx")
            root = Path("/")
        else:
            root = args.stage_dir.absolute()
            require(root != Path("/"), "staging root must not be the host root")
            safe_directory(root)

        def target(path):
            return root / path.relative_to("/")

        for name, data in assets.items():
            install_file(target(APP / "static" / name), data)
        install_file(target(APP / "static/wallet-config.json"), config_bytes)
        install_file(target(APP / "web.py"), regular_bytes(Path(__file__).with_name("web.py"), 262_144))
        install_file(target(SERVICE), service_config(origin, args.relay_port, args.upstream_host,
                                                   args.upstream_port, args.allow_local_dev).encode())
        install_file(target(NGINX), nginx_config(args.hostname, args.port, args.relay_port,
                                                args.allow_local_dev).encode())
        if cert_data is not None:
            safe_directory(target(TLS), 0o700)
            target(TLS).chmod(0o700)
            install_file(target(TLS / "fullchain.pem"), cert_data)
            if args.stage_dir is None:
                install_file(target(TLS / "key.pem"), key_data, 0o600)
        if args.stage_dir is not None:
            print(f"Staged static wallet and host configuration at {root}")
            print(f"Origin: {origin}; no host commands or network requests performed; TLS private key not staged")
            return
        nginx = shutil.which("nginx")
        require(nginx is not None, "nginx installation did not provide an executable")
        command(nginx, "-t")
        command("/usr/bin/systemctl", "daemon-reload")
        command("/usr/bin/systemctl", "enable", "sapio-wallet.service", "nginx.service")
        command("/usr/bin/systemctl", "restart", "sapio-wallet.service")
        command("/usr/bin/systemctl", "start", "nginx.service")
        command("/usr/bin/systemctl", "reload", "nginx.service")
        command("/usr/bin/systemctl", "is-active", "--quiet", "sapio-wallet.service", "nginx.service")
        ready(args, authority, config)
        print(f"Static wallet ready at {origin}/; HTTPS and pinned config verified locally")
        print("Enclave, KMS, setup and root identity unchanged. DNS and inbound HTTPS must already reach this parent.")
    except (OSError, ValueError, ssl.SSLError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"web installation failed: {error}\n")


if __name__ == "__main__":
    main()
