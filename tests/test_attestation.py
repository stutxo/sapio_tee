"""Real X509/COSE fixtures: these do not emulate or claim Nitro hardware."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import unittest

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

SPEC = importlib.util.spec_from_file_location(
    "verifier", Path(__file__).resolve().parents[1] / "scripts/verify-attestation.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def base58check_encode(payload):
    decoded = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(decoded, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = VERIFIER.BASE58_ALPHABET[remainder] + encoded
    for byte in decoded:
        if byte != 0:
            break
        encoded = "1" + encoded
    return encoded


# A structurally valid depth-0 extended public key carrying the secp256k1
# generator point; no seed exists or is needed for these verification tests.
def fixture_xpub(version):
    chain_code = bytes(range(32))
    generator = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    payload = version + b"\x00" + b"\x00" * 8 + chain_code + generator
    assert len(payload) == 78
    return base58check_encode(payload)


TESTNET_XPUB = fixture_xpub(bytes.fromhex("043587cf"))
MAINNET_XPUB = fixture_xpub(bytes.fromhex("0488b21e"))


def make_certificate(subject_key, subject_common, issuer_key, issuer_common,
                     not_before, not_after, ca):
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_common)]))
            .public_key(subject_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA384()))


class AttestationVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime.now(timezone.utc)
        cls.root_key = ec.generate_private_key(ec.SECP384R1())
        cls.leaf_key = ec.generate_private_key(ec.SECP384R1())
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test trust anchor")])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test NSM signer")])
        cls.root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                    .public_key(cls.root_key.public_key()).serial_number(1)
                    .not_valid_before(cls.now - timedelta(days=1)).not_valid_after(cls.now + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                    .sign(cls.root_key, hashes.SHA384()))
        cls.leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root_name)
                    .public_key(cls.leaf_key.public_key()).serial_number(2)
                    .not_valid_before(cls.now - timedelta(hours=1)).not_valid_after(cls.now + timedelta(hours=1))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(cls.root_key, hashes.SHA384()))
        cls.nonce = bytes(range(32))
        cls.pins = {i: bytes([i + 1]) * 48 for i in range(3)}
        cls.settings = {"key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                        "blockhash": "01" * 32, "network": "regtest"}
        cls.program_profile = {
            "protocol": "SignProgramV1",
            "inline_evaluators": [
                {"id": "0" * 64, "wasm_version": 1},
                {"id": "0" * 63 + "2", "wasm_version": 2},
            ],
            "registered_evaluators": [{
                "name": "pay-at-least/v1",
                "id": "c99794a01b53f5d41775d7f01e6d13afa072ab113540109267846af40d159111",
                "wasm_version": 1,
            }],
            "max_connections": 4,
            "request_timeout_secs": 30,
        }
        cls.identity = {"protocol": "sapio-tee/program-oracle/1", "mode": "nitro",
                        "xpub": TESTNET_XPUB, "settings": cls.settings,
                        "signing": cls.program_profile}
        cls.identity_json = json.dumps(cls.identity, separators=(",", ":"))

    def document(self):
        return {"module_id": "test-only", "digest": "SHA384", "timestamp": time.time_ns() // 1_000_000,
                "pcrs": self.pins, "certificate": self.leaf.public_bytes(serialization.Encoding.DER),
                "cabundle": [self.root.public_bytes(serialization.Encoding.DER)],
                "nonce": self.nonce, "user_data": hashlib.sha256(self.identity_json.encode()).digest()}

    def signed_response(self, document=None, identity=None, protected=None,
                        unprotected=None, tag=None, signing_key=None):
        identity_json = self.identity_json if identity is None else json.dumps(identity, separators=(",", ":"))
        document = self.document() if document is None else document.copy()
        document["user_data"] = hashlib.sha256(identity_json.encode()).digest()
        protected = cbor2.dumps({1: -35}) if protected is None else protected
        unprotected = {} if unprotected is None else unprotected
        payload = cbor2.dumps(document)
        signing_key = self.leaf_key if signing_key is None else signing_key
        der_sig = signing_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(der_sig)
        cose = [protected, unprotected, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")]
        encoded = cbor2.dumps(cbor2.CBORTag(tag, cose)) if tag is not None else cbor2.dumps(cose)
        return {"identity_json": identity_json, "document": base64.b64encode(encoded).decode()}

    def verify(self, response, **overrides):
        inputs = dict(response=response, settings=self.settings, program_profile=self.program_profile,
                      nonce=self.nonce, pins=self.pins,
                      trusted_root=self.root.public_bytes(serialization.Encoding.PEM), now_ms=time.time_ns() // 1_000_000)
        inputs.update(overrides)
        return VERIFIER.verify(**inputs)

    def test_valid_signed_identity(self):
        self.assertEqual(self.verify(self.signed_response()), self.identity)

    def test_missing_signing_profile_is_rejected(self):
        identity = {key: value for key, value in self.identity.items() if key != "signing"}
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(identity=identity))

    def test_genuine_unexpected_program_capabilities_are_rejected(self):
        registry = deepcopy(self.program_profile["registered_evaluators"])
        registry[0]["id"] = "ab" * 32
        cases = [
            {"registered_evaluators": registry},
            {"inline_evaluators": self.program_profile["inline_evaluators"][:1]},
            {"max_connections": 8},
        ]
        for changes in cases:
            identity = dict(self.identity, signing=self.program_profile | changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(self.signed_response(identity=identity))

    def test_genuine_wrong_program_identity_is_rejected(self):
        for changes in ({"protocol": "unsupported-identity-protocol"}, {"mode": "local-dev"},
                        {"signing": self.program_profile | {"max_connections": 4.0}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(self.signed_response(identity=self.identity | changes))

    def test_invalid_expected_profiles_fail_even_when_authentically_bound(self):
        inline = self.program_profile["inline_evaluators"]
        registered = self.program_profile["registered_evaluators"]
        cases = [
            {"protocol": "UnsupportedRequest"},
            {"inline_evaluators": [{"id": "0" * 64, "wasm_version": 2}]},
            {"inline_evaluators": [{"id": "ab" * 32, "wasm_version": 1}]},
            {"registered_evaluators": [registered[0] | {"id": "xyz"}]},
            {"registered_evaluators": [registered[0] | {"id": "0" * 64}]},
            {"registered_evaluators": registered * 2},
            {"inline_evaluators": inline * 2},
            {"registered_evaluators": [registered[0] | {"wasm_version": 3}]},
            {"registered_evaluators": [registered[0] | {"wasm_version": True}]},
            {"registered_evaluators": [registered[0] | {"name": ""}]},
            {"registered_evaluators": {}},
            {"max_connections": 0},
            {"request_timeout_secs": -1},
            {"request_timeout_secs": 1 << 64},
            {"request_timeout_secs": 30.0},
            {"unexpected": True},
        ]
        profiles = [self.program_profile | changes for changes in cases]
        profiles.append({key: value for key, value in self.program_profile.items()
                         if key != "registered_evaluators"})
        for profile in profiles:
            identity = dict(self.identity, signing=profile)
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                self.verify(self.signed_response(identity=identity), program_profile=profile)

    def test_modified_cose_payload_is_rejected(self):
        response = self.signed_response()
        cose = cbor2.loads(base64.b64decode(response["document"]))
        document = cbor2.loads(cose[2])
        document["pcrs"][0] = b"x" * 48
        cose[2] = cbor2.dumps(document)
        response["document"] = base64.b64encode(cbor2.dumps(cose)).decode()
        with self.assertRaises(Exception):
            self.verify(response)

    def test_xpub_substitution_is_rejected(self):
        response = self.signed_response()
        response["identity_json"] = self.identity_json.replace(TESTNET_XPUB, MAINNET_XPUB)
        with self.assertRaises(ValueError):
            self.verify(response)

    def test_wrong_challenge_settings_and_measurements_are_rejected(self):
        response = self.signed_response()
        cases = [{"nonce": b"x" * 32}, {"settings": dict(self.settings, network="bitcoin")},
                 {"pins": self.pins | {0: b"x" * 48}},
                 {"pins": {i: b"\0" * 48 for i in range(3)}}]
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.verify(response, **overrides)

    def test_signed_stale_document_is_rejected(self):
        document = self.document()
        document["timestamp"] -= 301000
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(document))

    def test_self_signed_untrusted_bundle_is_not_a_trust_anchor(self):
        other_key = ec.generate_private_key(ec.SECP384R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Different root")])
        other_root = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                      .public_key(other_key.public_key()).serial_number(3)
                      .not_valid_before(self.now - timedelta(days=1)).not_valid_after(self.now + timedelta(days=1))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                      .sign(other_key, hashes.SHA384()))
        with self.assertRaises(Exception):
            self.verify(self.signed_response(), trusted_root=other_root.public_bytes(serialization.Encoding.PEM))


    def test_expired_leaf_certificate_is_rejected(self):
        expired = make_certificate(self.leaf_key, "Expired leaf", self.root_key,
                                   "Test trust anchor", self.now - timedelta(days=2),
                                   self.now - timedelta(days=1), ca=False)
        document = self.document()
        document["certificate"] = expired.public_bytes(serialization.Encoding.DER)
        with self.assertRaises(VERIFIER.crypto.X509StoreContextError):
            self.verify(self.signed_response(document))

    def test_not_yet_valid_leaf_certificate_is_rejected(self):
        future = make_certificate(self.leaf_key, "Future leaf", self.root_key,
                                  "Test trust anchor", self.now + timedelta(hours=1),
                                  self.now + timedelta(days=1), ca=False)
        document = self.document()
        document["certificate"] = future.public_bytes(serialization.Encoding.DER)
        with self.assertRaises(VERIFIER.crypto.X509StoreContextError):
            self.verify(self.signed_response(document))

    def test_non_ca_issuer_is_rejected(self):
        intermediate_key = ec.generate_private_key(ec.SECP384R1())
        intermediate = make_certificate(intermediate_key, "Not a CA", self.root_key,
                                        "Test trust anchor", self.now - timedelta(days=1),
                                        self.now + timedelta(days=1), ca=False)
        leaf = make_certificate(self.leaf_key, "Leaf under non-CA", intermediate_key,
                                "Not a CA", self.now - timedelta(hours=1),
                                self.now + timedelta(hours=1), ca=False)
        document = self.document()
        document["certificate"] = leaf.public_bytes(serialization.Encoding.DER)
        document["cabundle"] = [intermediate.public_bytes(serialization.Encoding.DER)]
        with self.assertRaises(VERIFIER.crypto.X509StoreContextError):
            self.verify(self.signed_response(document))

    def test_expired_root_in_chain_is_rejected(self):
        expired_root_key = ec.generate_private_key(ec.SECP384R1())
        expired_root = make_certificate(expired_root_key, "Expired root", expired_root_key,
                                        "Expired root", self.now - timedelta(days=2),
                                        self.now - timedelta(days=1), ca=True)
        leaf = make_certificate(self.leaf_key, "Leaf under expired root", expired_root_key,
                                "Expired root", self.now - timedelta(days=2),
                                self.now + timedelta(days=1), ca=False)
        document = self.document()
        document["certificate"] = leaf.public_bytes(serialization.Encoding.DER)
        document["cabundle"] = [expired_root.public_bytes(serialization.Encoding.DER)]
        with self.assertRaises(VERIFIER.crypto.X509StoreContextError):
            self.verify(self.signed_response(document),
                        trusted_root=expired_root.public_bytes(serialization.Encoding.PEM))

    def test_wrong_curve_certificate_is_rejected(self):
        p256_key = ec.generate_private_key(ec.SECP256R1())
        p256_leaf = make_certificate(p256_key, "P-256 leaf", self.root_key,
                                     "Test trust anchor", self.now - timedelta(hours=1),
                                     self.now + timedelta(hours=1), ca=False)
        document = self.document()
        document["certificate"] = p256_leaf.public_bytes(serialization.Encoding.DER)
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(document))

    def test_future_timestamp_is_rejected(self):
        document = self.document()
        document["timestamp"] += 6000
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(document))

    def test_missing_challenge_field_is_rejected(self):
        document = self.document()
        del document["nonce"]
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(document))

    def test_wrong_digest_field_is_rejected(self):
        document = self.document()
        document["digest"] = "SHA256"
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(document))

    def test_ambiguous_cose_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(unprotected={1: -35}))

    def test_non_es384_protected_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(protected=cbor2.dumps({1: -37})))

    def test_cose_sign1_tag_is_accepted_and_other_tags_rejected(self):
        self.assertEqual(self.verify(self.signed_response(tag=18)), self.identity)
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(tag=17))

    def test_trailing_cbor_is_rejected(self):
        response = self.signed_response()
        encoded = base64.b64decode(response["document"]) + b"\x00"
        response["document"] = base64.b64encode(encoded).decode()
        with self.assertRaises(ValueError):
            self.verify(response)

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            VERIFIER.json_value('{"document": "a", "document": "b"}')

    def test_missing_or_partial_measurement_pins_are_rejected(self):
        response = self.signed_response()
        cases = [{}, {0: self.pins[0]}, {0: self.pins[0], 1: self.pins[1]},
                 {"0": self.pins[0], "1": self.pins[1], "2": self.pins[2]}]
        for pins in cases:
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                self.verify(response, pins=pins)

    def test_malformed_xpubs_are_rejected(self):
        corrupted = TESTNET_XPUB[:-1] + ("1" if TESTNET_XPUB[-1] != "1" else "2")
        # A structurally complete payload whose x-coordinate is not on secp256k1.
        bad_point_payload = (bytes.fromhex("043587cf") + b"\x00" + b"\x00" * 8
                             + bytes(range(32)) + b"\x02" + b"\xff" * 32)
        cases = ["", "not-an-xpub", corrupted, base58check_encode(bad_point_payload),
                 TESTNET_XPUB[:-4], 0]
        for xpub in cases:
            identity = self.identity | {"xpub": xpub}
            with self.subTest(xpub=str(xpub)[:40]), self.assertRaises(ValueError):
                self.verify(self.signed_response(identity=identity))

    def test_cross_network_xpub_is_rejected(self):
        bitcoin_settings = dict(self.settings, network="bitcoin")
        # A genuine mainnet-version key under a testnet settings claim.
        identity = self.identity | {"xpub": MAINNET_XPUB}
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(identity=identity))
        # A testnet-version key under a matching mainnet claim still fails:
        # the xpub version must agree with the claimed network.
        identity = self.identity | {"settings": bitcoin_settings}
        with self.assertRaises(ValueError):
            self.verify(self.signed_response(identity=identity), settings=bitcoin_settings)

    def test_mainnet_xpub_with_mainnet_settings_is_accepted(self):
        bitcoin_settings = dict(self.settings, network="bitcoin")
        identity = self.identity | {"xpub": MAINNET_XPUB, "settings": bitcoin_settings}
        result = self.verify(self.signed_response(identity=identity), settings=bitcoin_settings)
        self.assertEqual(result, identity)


if __name__ == "__main__":
    unittest.main()
