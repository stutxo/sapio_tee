#!/usr/bin/env python3
"""Verify a Sapio Nitro identity against caller-supplied trust anchors and pins."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import time

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from OpenSSL import crypto


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def json_value(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read_file(path):
    with Path(path).open("rb") as source:
        data = source.read(262145)
    require(len(data) <= 262144, "input exceeds 256 KiB")
    return data


def cbor_value(raw):
    require(isinstance(raw, bytes), "CBOR input must be bytes")
    stream = io.BytesIO(raw)
    value = cbor2.CBORDecoder(stream).decode()
    require(stream.read(1) == b"", "trailing CBOR data")
    return value


def validate_program_profile(profile):
    require(isinstance(profile, dict) and set(profile) == {
        "protocol", "inline_evaluators", "registered_evaluators",
        "max_connections", "request_timeout_secs",
    }, "invalid program profile fields")
    require(profile["protocol"] == "SignProgramV1", "unsupported program wire protocol")
    reserved = {"0" * 64: 1, "0" * 63 + "2": 2}
    seen = set()
    for kind in ("inline_evaluators", "registered_evaluators"):
        entries = profile[kind]
        require(isinstance(entries, list), "evaluator registry must be an array")
        for entry in entries:
            fields = {"id", "wasm_version"}
            if kind == "registered_evaluators":
                fields.add("name")
            require(isinstance(entry, dict) and set(entry) == fields, "invalid evaluator fields")
            evaluator_id = entry["id"]
            require(isinstance(evaluator_id, str) and len(evaluator_id) == 64
                    and all(char in "0123456789abcdef" for char in evaluator_id),
                    "invalid evaluator ID")
            require(evaluator_id not in seen, "duplicate evaluator ID")
            seen.add(evaluator_id)
            version = entry["wasm_version"]
            require(type(version) is int and version in (1, 2), "unsupported WASM version")
            if kind == "inline_evaluators":
                require(reserved.get(evaluator_id) == version, "invalid reserved inline ABI")
            else:
                require(evaluator_id not in reserved, "reserved ID cannot be registered")
                require(isinstance(entry["name"], str) and entry["name"].strip(),
                        "missing registered evaluator name")
    for field in ("max_connections", "request_timeout_secs"):
        require(type(profile[field]) is int and 0 < profile[field] <= 0xFFFFFFFF,
                "program limits must be positive bounded integers")


def verify(response, settings, program_profile, nonce, pins, trusted_root, now_ms):
    # This is an independent trust input, never a profile learned from the host.
    validate_program_profile(program_profile)
    require(set(response) == {"document", "identity_json"}, "unexpected response fields")
    encoded = base64.b64decode(response["document"], validate=True)
    require(len(encoded) <= 16384, "attestation document too large")
    cose = cbor_value(encoded)
    if isinstance(cose, cbor2.CBORTag):
        require(cose.tag == 18, "expected COSE_Sign1 tag")
        cose = cose.value
    require(isinstance(cose, (list, tuple)) and len(cose) == 4, "invalid COSE_Sign1")
    protected, unprotected, payload, signature = cose
    require(isinstance(unprotected, dict), "invalid unprotected header")
    require(cbor_value(protected) == {1: -35}, "expected protected ES384 algorithm")
    require(1 not in unprotected, "ambiguous COSE algorithm")
    require(isinstance(signature, bytes) and len(signature) == 96, "invalid ES384 signature")
    document = cbor_value(payload)
    require(isinstance(document, dict), "invalid attestation payload")

    # Only the independently supplied root is trusted. The document's cabundle
    # supplies intermediates, not trust anchors. OpenSSL checks CA constraints,
    # path signatures, and certificate validity against the verifier's clock.
    root = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_root)
    store = crypto.X509Store()
    store.add_cert(root)
    certificate = document["certificate"]
    require(isinstance(certificate, bytes), "invalid leaf certificate")
    leaf = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
    bundle = document["cabundle"]
    require(isinstance(bundle, list) and len(bundle) <= 10, "invalid certificate chain")
    chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, item) for item in bundle]
    crypto.X509StoreContext(store, leaf, chain).verify_certificate()
    public_key = x509.load_der_x509_certificate(certificate).public_key()
    require(isinstance(public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.curve, ec.SECP384R1), "expected P-384 certificate key")
    r = int.from_bytes(signature[:48], "big")
    s = int.from_bytes(signature[48:], "big")
    signed = cbor2.dumps(["Signature1", protected, b"", payload])
    public_key.verify(utils.encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA384()))

    require(document["digest"] == "SHA384", "expected SHA384 measurements")
    for index, expected in pins.items():
        require(len(expected) == 48 and any(expected), "zero or invalid measurement pin")
        require(document["pcrs"].get(index) == expected, f"PCR{index} mismatch")
    timestamp = document["timestamp"]
    require(type(timestamp) is int and now_ms - 300000 <= timestamp <= now_ms + 5000,
            "stale or future attestation timestamp")
    require(16 <= len(nonce) <= 64, "nonce must contain 16..64 bytes")
    require(document.get("nonce") == nonce, "challenge nonce mismatch")
    identity_json = response["identity_json"]
    require(isinstance(identity_json, str), "identity_json must be a string")
    require(document.get("user_data") == hashlib.sha256(identity_json.encode("utf-8")).digest(),
            "identity is not bound to attestation")
    identity = json_value(identity_json)
    require(isinstance(identity, dict) and set(identity) == {
        "protocol", "mode", "xpub", "settings", "signing",
    }, "unexpected identity fields")
    require(identity["protocol"] == "sapio-tee/program-oracle/1"
            and identity["mode"] == "nitro", "not a Nitro program signer identity")
    # Validate both sides so Python's bool/int equality cannot accept a
    # differently typed capability profile as equal to the expected one.
    validate_program_profile(identity["signing"])
    require(identity["signing"] == program_profile, "program profile mismatch")
    require(identity["settings"] == settings, "setup settings mismatch")
    require(isinstance(identity["xpub"], str) and identity["xpub"], "missing xpub")
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--response", required=True, help="saved POST /attestation response JSON")
    parser.add_argument("--settings", required=True, help="independently selected setup JSON")
    parser.add_argument("--program-profile", required=True,
                        help="independently reviewed expected program profile JSON")
    parser.add_argument("--nonce", required=True, help="fresh client challenge, hex")
    parser.add_argument("--root-cert", required=True, help="independently trusted AWS Nitro root PEM")
    for index in range(3):
        parser.add_argument(f"--pcr{index}", required=True, help="independently reproduced measurement, hex")
    args = parser.parse_args()
    try:
        identity = verify(
            json_value(read_file(args.response)),
            json_value(read_file(args.settings)),
            json_value(read_file(args.program_profile)),
            bytes.fromhex(args.nonce),
            {index: bytes.fromhex(getattr(args, f"pcr{index}")) for index in range(3)},
            read_file(args.root_cert),
            time.time_ns() // 1_000_000,
        )
    except (ValueError, TypeError, KeyError, OSError, crypto.Error, cbor2.CBORDecodeError) as error:
        print(f"attestation rejected: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Cryptographic backend exceptions also fail closed, with no identity output.
        print(f"attestation rejected: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(identity, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
