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
                        "xpub": "fixture-identity", "settings": cls.settings,
                        "signing": cls.program_profile}
        cls.identity_json = json.dumps(cls.identity, separators=(",", ":"))

    def document(self):
        return {"module_id": "test-only", "digest": "SHA384", "timestamp": time.time_ns() // 1_000_000,
                "pcrs": self.pins, "certificate": self.leaf.public_bytes(serialization.Encoding.DER),
                "cabundle": [self.root.public_bytes(serialization.Encoding.DER)],
                "nonce": self.nonce, "user_data": hashlib.sha256(self.identity_json.encode()).digest()}

    def signed_response(self, document=None, identity=None):
        identity_json = self.identity_json if identity is None else json.dumps(identity, separators=(",", ":"))
        document = self.document() if document is None else document.copy()
        document["user_data"] = hashlib.sha256(identity_json.encode()).digest()
        protected = cbor2.dumps({1: -35})
        payload = cbor2.dumps(document)
        der_sig = self.leaf_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(der_sig)
        cose = cbor2.dumps([protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")])
        return {"identity_json": identity_json, "document": base64.b64encode(cose).decode()}

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
        response["identity_json"] = self.identity_json.replace("fixture-identity", "attacker-key")
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


if __name__ == "__main__":
    unittest.main()
