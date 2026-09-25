import { aggregateRecoveryKeys, generateRecoveryKey, recoveryPublicKey, signRecovery, tweakRecoveryOutput } from "./recovery.js";
import { walletCall } from "./wallet.js";

"use strict";

(() => {
  const ORIGIN = location.origin;
  const RP_ID = location.hostname;
  const STORAGE_KEY = "sapio.passkey.wallet.v2";
  const LEGACY_STORAGE_KEY = "sapio.passkey.wallet.v1";
  const MAX_SATS = 2100000000000000;
  const MAX_VIEW = 1048576;
  const MAX_JSON = 1000000;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder("utf-8", { fatal: true });
  const $ = (id) => document.getElementById(id);
  let configurationPromise;
  const state = {
    config: null, context: null, signUrl: null, record: null, wallet: null, parameters: null, recovery: null,
    retainedMetadata: null, legacyMetadata: null,
    prepared: null, signed: null, busy: false, controller: null,
    revision: 0, signRequestSent: false,
  };

  function requireThat(condition, message) {
    if (!condition) throw new Error(message);
  }

  function object(value, label) {
    requireThat(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object.`);
    return value;
  }

  function hex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function unhex(value, label, length, maximum = MAX_VIEW) {
    requireThat(typeof value === "string" && value.length % 2 === 0 && value.length <= maximum * 2 && /^[0-9a-f]*$/.test(value), `${label} must be bounded, lowercase hex.`);
    requireThat(length === undefined || value.length === length * 2, `${label} has the wrong length.`);
    const bytes = new Uint8Array(value.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }

  function concat(...parts) {
    const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  }

  function equal(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  function u32(value) {
    const result = new Uint8Array(4);
    new DataView(result.buffer).setUint32(0, value, true);
    return result;
  }

  function u64(value) {
    const result = new Uint8Array(8);
    new DataView(result.buffer).setBigUint64(0, BigInt(value), true);
    return result;
  }

  async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
  async function transactionId(bytes) { return hex((await sha256(await sha256(bytes))).reverse()); }

  async function taggedHash(tag, bytes) {
    const tagHash = await sha256(textEncoder.encode(tag));
    return sha256(concat(tagHash, tagHash, bytes));
  }

  function recoveryKeys(value) {
    requireThat(Array.isArray(value) && value.length === 2, "Recovery requires exactly two Bitcoin public keys.");
    for (const key of value) {
      const bytes = unhex(key, "Recovery public key", 33);
      requireThat(bytes[0] === 2 || bytes[0] === 3, "Recovery public keys must be compressed secp256k1 points (02 or 03).");
    }
    requireThat(value[0].slice(2) !== value[1].slice(2), "The recovery keys must be distinct, including their x coordinates.");
    return [...value].sort();
  }

  function setupRecoveryKeys() {
    return recoveryKeys(["recovery-public-1", "recovery-public-2"].map((id) => $(id).value.trim().toLowerCase()));
  }

  async function recoveryLeaf(keys) {
    const publicKeys = recoveryKeys(keys);
    const aggregate = unhex(await aggregateRecoveryKeys(publicKeys), "Recovery aggregate key", 32);
    const script = concat(Uint8Array.of(0x20), aggregate, Uint8Array.of(0xac));
    const leafHash = await taggedHash("TapLeaf", concat(Uint8Array.of(0xc0, script.length), script));
    return { public_keys: publicKeys, aggregate_key: hex(aggregate), leaf_script: hex(script), leaf_hash: hex(leafHash) };
  }

  async function recoveryDescriptor(leaf, internalKey) {
    const key = unhex(internalKey, "Taproot internal key", 32);
    const tweak = await taggedHash("TapTweak", concat(key, unhex(leaf.leaf_hash, "Recovery leaf hash", 32)));
    const output = await tweakRecoveryOutput(internalKey, hex(tweak));
    const outputKey = unhex(output.output_key, "Taproot output key", 32);
    requireThat(output.parity === 0 || output.parity === 1, "Invalid Taproot output parity.");
    return { ...leaf, control_block: hex(concat(Uint8Array.of(0xc0 | output.parity), key)), script: concat(Uint8Array.of(0x51, 0x20), outputKey) };
  }

  function checkRecoveryDescriptor(value, expected, withSighash = false) {
    const descriptor = object(value, "Recovery descriptor");
    const fields = ["public_keys", "aggregate_key", "leaf_script", "leaf_hash", "control_block"];
    requireThat(Object.keys(descriptor).length === fields.length + Number(withSighash) && fields.every((field) => Object.hasOwn(descriptor, field)) && (!withSighash || Object.hasOwn(descriptor, "sighash")), "Recovery descriptor has unexpected or missing fields.");
    requireThat(Array.isArray(descriptor.public_keys) && descriptor.public_keys.length === 2 && descriptor.public_keys.every((key, index) => key === expected.public_keys[index]), "Wallet recovery keys differ from the canonical enrolled pair.");
    for (const field of fields.slice(1)) requireThat(descriptor[field] === expected[field], `Wallet recovery ${field} differs from the independently computed single-leaf policy.`);
  }

  async function recoverySighash(view, leafHash) {
    const input = view.inputs[0];
    // BIP341: epoch 0, SIGHASH_ALL, ext_flag 1, input 0, no annex,
    // followed by the BIP342 leaf/key-version/code-separator extension.
    const hashes = await Promise.all([
      sha256(input.outpoint),
      sha256(u64(input.value)),
      sha256(concat(compact(input.prevoutScript.length), input.prevoutScript)),
      sha256(u32(input.sequence)),
      sha256(concat(...view.outputs.map((output) => concat(u64(output.value), compact(output.script.length), output.script)))),
    ]);
    return taggedHash("TapSighash", concat(Uint8Array.of(0, 1), u32(view.version), u32(view.locktime), ...hashes, Uint8Array.of(2), u32(0), unhex(leafHash, "Recovery leaf hash", 32), Uint8Array.of(0), u32(0xffffffff)));
  }

  function base64url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeCredentialId(value) {
    requireThat(typeof value === "string" && /^[A-Za-z0-9_-]{1,1400}$/.test(value) && value.length % 4 !== 1, "Credential ID must be unpadded base64url.");
    const bytes = Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), (char) => char.charCodeAt(0));
    requireThat(bytes.length > 0 && bytes.length <= 1024 && base64url(bytes) === value, "Credential ID is invalid or too long.");
    return bytes;
  }

  function decodeBase64(value, label) {
    requireThat(typeof value === "string" && value.length > 0 && value.length <= 3 * MAX_VIEW && value.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value), `${label} must be bounded base64.`);
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }

  function sats(value, label, allowZero = false) {
    requireThat(Number.isSafeInteger(value) && value >= (allowZero ? 0 : 1) && value <= MAX_SATS, `${label} must be whole satoshis within Bitcoin’s supply limit.`);
    return value;
  }

  function integerField(id, label, maximum, allowZero = false) {
    const value = $(id).value.trim();
    requireThat(/^(0|[1-9][0-9]*)$/.test(value), `${label} must be a whole decimal integer, without separators.`);
    const parsed = Number(value);
    requireThat(Number.isSafeInteger(parsed) && parsed >= (allowZero ? 0 : 1) && parsed <= maximum, `${label} is outside the supported range.`);
    return parsed;
  }

  // BIP173/BIP350: independently validate the address, not just a supplied script.
  function witnessAddress(address, network) {
    requireThat(typeof address === "string" && address.length >= 14 && address.length <= 90 && (address === address.toLowerCase() || address === address.toUpperCase()), "Use a native SegWit address without mixed case.");
    const normalized = address.toLowerCase();
    const separator = normalized.lastIndexOf("1");
    const prefix = network === "bitcoin" ? "bc" : network === "regtest" ? "bcrt" : "tb";
    requireThat(separator === prefix.length && normalized.slice(0, separator) === prefix, `Recipient must use the ${prefix}1 native SegWit prefix for ${network}.`);
    const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const values = Array.from(normalized.slice(separator + 1), (char) => alphabet.indexOf(char));
    requireThat(values.length >= 7 && values.every((value) => value >= 0), "Invalid characters or missing checksum in SegWit address.");
    const expanded = [...Array.from(prefix, (char) => char.charCodeAt(0) >> 5), 0, ...Array.from(prefix, (char) => char.charCodeAt(0) & 31)];
    let checksum = 1;
    const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    for (const value of [...expanded, ...values]) {
      const top = checksum >>> 25;
      checksum = (((checksum & 0x1ffffff) << 5) ^ value) >>> 0;
      for (let bit = 0; bit < 5; bit++) if ((top >>> bit) & 1) checksum = (checksum ^ generators[bit]) >>> 0;
    }
    const version = values[0];
    requireThat(version <= 16 && checksum === (version === 0 ? 1 : 0x2bc830a3), "SegWit address checksum or bech32/bech32m encoding is invalid.");
    let accumulator = 0;
    let bits = 0;
    const program = [];
    for (const value of values.slice(1, -6)) {
      accumulator = ((accumulator << 5) | value) & 0xfff;
      bits += 5;
      if (bits >= 8) { bits -= 8; program.push((accumulator >>> bits) & 255); }
    }
    requireThat(bits < 5 && ((accumulator << (8 - bits)) & 255) === 0, "SegWit address has invalid padding.");
    requireThat(program.length >= 2 && program.length <= 40 && (version !== 0 || program.length === 20 || program.length === 32), "SegWit witness program has an invalid length.");
    return { address: normalized, version, program: Uint8Array.from(program), script: Uint8Array.from([version === 0 ? 0 : 0x50 + version, program.length, ...program]) };
  }

  class Reader {
    constructor(bytes, label) { this.bytes = bytes; this.label = label; this.offset = 0; this.data = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }
    take(size) {
      requireThat(Number.isSafeInteger(size) && size >= 0 && size <= this.bytes.length - this.offset, `${this.label} is truncated or has an invalid length.`);
      const value = this.bytes.subarray(this.offset, this.offset + size);
      this.offset += size;
      return value;
    }
    byte() { return this.take(1)[0]; }
    uint32() { const offset = this.offset; this.take(4); return this.data.getUint32(offset, true); }
    amount() { const offset = this.offset; this.take(8); return sats(Number(this.data.getBigUint64(offset, true)), `${this.label} amount`, true); }
    compact() {
      const prefix = this.byte();
      if (prefix < 253) return prefix;
      let value;
      if (prefix === 253) { const offset = this.offset; this.take(2); value = this.data.getUint16(offset, true); requireThat(value >= 253, "Noncanonical CompactSize."); }
      else if (prefix === 254) { value = this.uint32(); requireThat(value > 65535, "Noncanonical CompactSize."); }
      else { throw new Error(`${this.label} has an unsupported oversized CompactSize.`); }
      requireThat(value <= MAX_VIEW, `${this.label} exceeds supported limits.`);
      return value;
    }
    sized() { return this.take(this.compact()); }
    end() { requireThat(this.offset === this.bytes.length, `${this.label} has unexpected trailing bytes.`); }
  }

  function compact(value) {
    if (value < 253) return Uint8Array.of(value);
    if (value <= 65535) return Uint8Array.of(253, value & 255, value >>> 8);
    return concat(Uint8Array.of(254), u32(value));
  }

  function serializeTransaction(tx) {
    return concat(u32(tx.version), compact(tx.inputs.length), ...tx.inputs.map((input) => concat(input.outpoint, compact(input.script.length), input.script, u32(input.sequence))), compact(tx.outputs.length), ...tx.outputs.map((output) => concat(u64(output.value), compact(output.script.length), output.script)), u32(tx.locktime));
  }

  function parseView(bytes) {
    const reader = new Reader(bytes, "Transaction view");
    const version = reader.uint32();
    const locktime = reader.uint32();
    requireThat(reader.uint32() === 0, "The selected input must be the only input.");
    requireThat(reader.uint32() === 1, "Only one-input spends are supported.");
    const input = { outpoint: reader.take(36), sequence: reader.uint32(), value: reader.amount(), prevoutScript: reader.take(reader.uint32()), script: new Uint8Array() };
    const outputCount = reader.uint32();
    requireThat(outputCount === 1 || outputCount === 2, "Expected recipient output and optional change only.");
    const outputs = [];
    for (let index = 0; index < outputCount; index++) outputs.push({ value: reader.amount(), script: reader.take(reader.uint32()) });
    const internalKey = reader.take(32);
    requireThat(reader.uint32() === 0, "Taproot annexes are not supported.");
    reader.end();
    return { version, locktime, inputs: [input], outputs, internalKey };
  }

  function checkPsbt(encoded, prepared, signed) {
    const { unsignedTransaction, view, recovery, draft } = prepared;
    const isRecovery = draft.path === "recovery";
    const reader = new Reader(decodeBase64(encoded, "PSBT"), "PSBT");
    requireThat(equal(reader.take(5), Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff)), "Invalid PSBT magic.");
    const input = view.inputs[0];
    const required = new Map([
      ["01", concat(u64(input.value), compact(input.prevoutScript.length), input.prevoutScript)],
      ["03", u32(1)],
      ["17", view.internalKey],
      ["18", unhex(recovery.leaf_hash, "Recovery leaf hash", 32)],
    ]);
    if (isRecovery) required.set(`15${recovery.control_block}`, concat(unhex(recovery.leaf_script, "Recovery leaf script", 34), Uint8Array.of(0xc0)));
    let unsignedFound = false;
    let finalWitnessFound = false;
    for (let map = 0; map < 2 + view.outputs.length; map++) {
      const keys = new Set();
      while (true) {
        const key = reader.sized();
        if (key.length === 0) break;
        const keyHex = hex(key);
        requireThat(!keys.has(keyHex), "PSBT contains a duplicate key.");
        keys.add(keyHex);
        const value = reader.sized();
        if (map === 0) {
          requireThat(keyHex === "00" && equal(value, unsignedTransaction), "PSBT must contain only the exact reviewed unsigned transaction in its global map.");
          unsignedFound = true;
        } else if (map === 1) {
          if (required.has(keyHex)) {
            requireThat(equal(value, required.get(keyHex)), "PSBT funding, sighash, internal key, or recovery tree differs from the verified transaction.");
          } else if (keyHex === "08" && signed) {
            requireThat(equal(value, signed.witness), "PSBT final witness differs from the exported signed transaction.");
            finalWitnessFound = true;
          } else if (keyHex === "13" && signed && !isRecovery) {
            requireThat(equal(value, signed.signature), "PSBT key-path signature differs from the exported transaction.");
          } else if (keyHex === `14${recovery.aggregate_key}${recovery.leaf_hash}` && signed && isRecovery) {
            requireThat(equal(value, signed.signature), "PSBT script-path signature differs from the locally signed transaction.");
          } else {
            throw new Error("PSBT contains unexpected input metadata, a signature, or an alternate spending path.");
          }
        } else {
          throw new Error("PSBT contains unexpected output metadata.");
        }
      }
      if (map === 1 && !signed) requireThat([...required.keys()].every((key) => keys.has(key)), "Prepared PSBT is missing the exact funding data, SIGHASH_ALL, or committed Taproot tree.");
    }
    reader.end();
    requireThat(unsignedFound, "Only PSBT v0 with an unsigned transaction is supported.");
    requireThat(!signed || finalWitnessFound, "Signed PSBT is missing the exact finalized witness.");
  }

  function parseSignedTransaction(encoded, prepared, localSignature) {
    const reader = new Reader(unhex(encoded, "Signed transaction"), "Signed transaction");
    const version = reader.uint32();
    requireThat(reader.byte() === 0 && reader.byte() === 1, "Expected a SegWit signed transaction.");
    requireThat(reader.compact() === 1, "Signed transaction changed the input count.");
    const inputs = [{ outpoint: reader.take(36), script: reader.sized(), sequence: reader.uint32() }];
    const count = reader.compact();
    requireThat(count === 1 || count === 2, "Signed transaction changed the output count.");
    const outputs = [];
    for (let index = 0; index < count; index++) outputs.push({ value: reader.amount(), script: reader.sized() });
    const witnessStart = reader.offset;
    const isRecovery = prepared.draft.path === "recovery";
    requireThat(reader.compact() === (isRecovery ? 3 : 1), "Signed witness has the wrong number of items or an unexpected annex.");
    const signature = reader.sized();
    requireThat(signature.length === 65 && signature[64] === 1, "Expected exactly a 65-byte Taproot SIGHASH_ALL signature committing to every input and output.");
    if (isRecovery) {
      requireThat(equal(signature.subarray(0, 64), unhex(localSignature, "Locally produced recovery signature", 64)), "Finalization replaced the locally produced recovery signature.");
      requireThat(equal(reader.sized(), unhex(prepared.recovery.leaf_script, "Recovery leaf script", 34)), "Final witness substituted the recovery script.");
      requireThat(equal(reader.sized(), unhex(prepared.recovery.control_block, "Recovery control block", 33)), "Final witness substituted the single-leaf recovery control block.");
    }
    const witness = reader.bytes.subarray(witnessStart, reader.offset);
    const locktime = reader.uint32();
    reader.end();
    return { version, inputs, outputs, locktime, signature, witness };
  }

  function validateConfig(value) {
    const config = object(value, "Wallet configuration");
    requireThat(config.origin === ORIGIN && config.rp_id === RP_ID && location.origin === ORIGIN, `Open this wallet at exactly ${ORIGIN}; the RP ID and origin must match.`);
    requireThat(["bitcoin", "testnet", "testnet4", "signet", "regtest"].includes(config.network), "Wallet configuration has an unsupported Bitcoin network.");
    unhex(config.genesis_hash, "Network genesis", 32);
    unhex(config.module_sha256, "Module SHA-256", 32);
    requireThat(typeof config.xpub === "string" && /^[1-9A-HJ-NP-Za-km-z]{100,120}$/.test(config.xpub), "Wallet configuration has an invalid extended public key.");
    requireThat(Number.isInteger(config.module_bytes) && config.module_bytes > 0 && config.module_bytes <= 65536 && typeof config.local_dev === "boolean", "Wallet module size or environment is invalid.");
    witnessAddress(config.default_recipient, config.network);
    return config;
  }

  async function readJson(response, label) {
    requireThat(response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() === "application/json", `${label} returned a non-JSON response.`);
    const declared = response.headers.get("content-length");
    requireThat(declared === null || (/^[0-9]+$/.test(declared) && Number(declared) <= MAX_JSON), `${label} exceeds the wallet’s size limit.`);
    requireThat(response.body, `${label} returned no response body.`);
    const reader = response.body.getReader();
    const bytes = new Uint8Array(MAX_JSON);
    let size = 0;
    try {
      while (true) {
        state.controller.signal.throwIfAborted();
        const { value, done } = await reader.read();
        if (done) break;
        requireThat(value.length <= MAX_JSON - size, `${label} exceeds the wallet’s size limit.`);
        bytes.set(value, size);
        size += value.length;
      }
    } finally {
      try { await reader.cancel(); } catch { /* Preserve the original request error. */ }
      reader.releaseLock();
    }
    let value;
    try { value = JSON.parse(textDecoder.decode(bytes.subarray(0, size))); }
    catch { throw new Error(`${label} returned invalid JSON.`); }
    if (!response.ok) throw new Error(typeof value?.error === "string" ? value.error : `${label} failed (HTTP ${response.status}).`);
    return object(value, label);
  }

  async function requestSignature(request) {
    const body = textEncoder.encode(JSON.stringify(request));
    requireThat(body.length > 0 && body.length <= MAX_JSON, "Signer request exceeds the transport size limit.");
    state.controller.signal.throwIfAborted();
    state.signRequestSent = true;
    const response = await fetch(state.signUrl, {
      method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" },
      body, credentials: "omit", mode: new URL(state.signUrl).origin === ORIGIN ? "same-origin" : "cors",
      cache: "no-store", redirect: "error", signal: state.controller.signal,
    });
    return readJson(response, "Enclave signing transport");
  }

  function checkConfiguration() {
    requireThat(state.config && state.context && state.config.origin === ORIGIN && state.config.rp_id === RP_ID
      && location.origin === ORIGIN && location.hostname === RP_ID, "The pinned wallet configuration is unavailable or this origin changed. Public metadata is retained for export; reload this exact origin to load its configuration.");
    state.controller.signal.throwIfAborted();
  }

  async function policyParameters(publicKey, leafHash) {
    const key = unhex(publicKey, "Passkey public key", 33);
    requireThat(key[0] === 2 || key[0] === 3, "Passkey public key must be a compressed P-256 point.");
    const origin = textEncoder.encode(state.config.origin);
    return concat(textEncoder.encode("SPK2"), unhex(state.config.genesis_hash, "Network genesis", 32), key, unhex(leafHash, "Recovery leaf hash", 32), await sha256(textEncoder.encode(state.config.rp_id)), u32(origin.length), origin);
  }

  function validateRecord(value) {
    const record = object(value, "Public metadata");
    const keys = ["version", "credential_id", "public_key", "recovery_keys", "internal_key", "rp_id", "origin", "network", "xpub", "module_sha256", "program_id", "address"];
    requireThat(record.version === 2, "Unsupported metadata version. Earlier wallets have no committed recovery tree and cannot be upgraded to this address. The original metadata is retained for export; do not enroll a replacement expecting the same address.");
    requireThat(Object.keys(record).length === keys.length && keys.every((key) => Object.hasOwn(record, key)), "Use an unmodified version-2 public metadata backup with exactly the expected fields.");
    decodeCredentialId(record.credential_id);
    const key = unhex(record.public_key, "Passkey public key", 33);
    requireThat(key[0] === 2 || key[0] === 3, "Metadata public key is not compressed P-256.");
    const recovery = recoveryKeys(record.recovery_keys);
    requireThat(recovery.every((key, index) => key === record.recovery_keys[index]), "Metadata recovery keys must be in canonical sorted order.");
    unhex(record.internal_key, "Taproot internal key", 32);
    unhex(record.program_id, "Program ID", 32);
    unhex(record.module_sha256, "Module SHA-256", 32);
    requireThat(typeof record.xpub === "string" && /^[1-9A-HJ-NP-Za-km-z]{100,120}$/.test(record.xpub), "Metadata has an invalid extended public key.");
    requireThat(record.origin === ORIGIN && record.rp_id === RP_ID && ["bitcoin", "testnet", "testnet4", "signet", "regtest"].includes(record.network), "Metadata has an unsupported origin, relying party, or network.");
    const address = witnessAddress(record.address, record.network);
    requireThat(address.version === 1 && address.program.length === 32 && record.address === address.address, "Metadata address must be canonical native Taproot.");
    return record;
  }

  async function deriveWallet(publicKey, recoveryKeys, leaf) {
    leaf ??= await recoveryLeaf(recoveryKeys);
    const parameters = await policyParameters(publicKey, leaf.leaf_hash);
    const wallet = await walletCall("wallet", state.context, { public_key: publicKey, recovery_keys: leaf.public_keys }, state.controller.signal);
    requireThat(equal(unhex(wallet.parameters, "Policy parameters", undefined, 4096), parameters), "Wallet policy parameters differ from the independently encoded passkey and recovery policy.");
    unhex(wallet.program_id, "Program ID", 32);
    const recovery = await recoveryDescriptor(leaf, wallet.internal_key);
    checkRecoveryDescriptor(wallet.recovery, recovery);
    const address = witnessAddress(wallet.address, state.config.network);
    requireThat(address.version === 1 && address.program.length === 32 && wallet.address === address.address, "Wallet address must be canonical native Taproot.");
    requireThat(equal(unhex(wallet.script_pubkey, "Wallet script"), recovery.script) && equal(address.script, recovery.script), "Wallet script or address does not commit to the independently computed two-key recovery tree.");
    const funding = object(wallet.synthetic_funding, "Synthetic funding");
    unhex(funding.txid, "Synthetic transaction ID", 32);
    requireThat(funding.vout === 0 && funding.value_sats === 100000, "Wallet synthetic funding differs from the documented demo fixture.");
    return { wallet, parameters, recovery };
  }

  function metadata(publicKey, credentialId, derived) {
    return { version: 2, credential_id: credentialId, public_key: publicKey, recovery_keys: derived.recovery.public_keys, internal_key: derived.wallet.internal_key, rp_id: state.config.rp_id, origin: state.config.origin, network: state.config.network, xpub: state.config.xpub, module_sha256: state.config.module_sha256, program_id: derived.wallet.program_id, address: derived.wallet.address };
  }

  function hasMetadata() { return !!(state.record || state.retainedMetadata !== null || state.legacyMetadata !== null); }

  function saveRecord() {
    const content = JSON.stringify(state.record);
    try {
      const existing = localStorage.getItem(STORAGE_KEY);
      if (existing !== null && existing !== state.retainedMetadata && JSON.stringify(JSON.parse(existing)) !== content) {
        $("wallet-note").textContent = "Different metadata appeared in browser storage. It was NOT overwritten. Export this wallet now and preserve the existing backup separately.";
        return;
      }
      localStorage.setItem(STORAGE_KEY, content);
      state.retainedMetadata = content;
      $("wallet-note").textContent = "Only public metadata is saved. Export it now and independently back up both recovery keys; this file cannot replace any private key.";
    } catch {
      $("wallet-note").textContent = "Browser storage is unavailable or contains incompatible data. Export public metadata before closing; both recovery private keys need separate backups.";
    }
  }

  function clearRecoverySecrets() {
    for (const id of ["recovery-private-1", "recovery-private-2"]) { $(id).value = ""; $(id).type = "password"; }
    $("show-recovery-secrets").checked = false;
  }

  function invalidate() {
    state.revision++;
    state.prepared = null;
    state.signed = null;
    $("review").hidden = true;
    $("result").hidden = true;
    $("transaction-hex").value = "";
    $("signed-psbt").value = "";
    $("result-txid").value = "";
    renderControls();
  }

  function clearWallet(forget = false) {
    invalidate();
    state.wallet = null;
    state.parameters = null;
    state.recovery = null;
    clearRecoverySecrets();
    if (forget) {
      state.record = null;
      state.retainedMetadata = null;
      state.legacyMetadata = null;
      for (const id of ["recovery-public-1", "recovery-public-2"]) $(id).value = "";
      try { localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(LEGACY_STORAGE_KEY); } catch { /* In-memory metadata is still forgotten. */ }
    }
    $("wallet-details").hidden = true;
    $("wallet-address").value = "";
    $("identity-program").textContent = "—";
    $("identity-passkey").textContent = "—";
    $("identity-internal").textContent = "—";
    $("identity-recovery").textContent = "—";
    $("identity-leaf").textContent = "—";
    renderControls();
  }

  function acceptWallet(record, derived) {
    state.controller.signal.throwIfAborted();
    invalidate();
    state.record = record;
    state.wallet = derived.wallet;
    state.parameters = derived.parameters;
    state.recovery = derived.recovery;
    $("wallet-address").value = record.address;
    $("identity-program").textContent = record.program_id;
    $("identity-passkey").textContent = record.public_key;
    $("identity-internal").textContent = record.internal_key;
    $("identity-recovery").textContent = record.recovery_keys.join("\n");
    $("identity-leaf").textContent = `${derived.recovery.aggregate_key} / ${derived.recovery.leaf_hash}`;
    record.recovery_keys.forEach((key, index) => { $(`recovery-public-${index + 1}`).value = key; });
    $("wallet-details").hidden = false;
    saveRecord();
    autofillDemo();
  }

  async function restoreRecord(value) {
    try {
      const record = validateRecord(value);
      // Preserve even incompatible metadata for export; only explicit Forget deletes it.
      state.record = record;
      for (const field of ["rp_id", "origin", "network", "xpub", "module_sha256"]) requireThat(record[field] === state.config[field], `Metadata ${field} does not match this pinned configuration. Export the preserved metadata and return to the original origin, root, and module; do not enroll a replacement expecting the same address.`);
      const derived = await deriveWallet(record.public_key, record.recovery_keys);
      requireThat(derived.wallet.program_id === record.program_id && derived.wallet.address === record.address && derived.wallet.internal_key === record.internal_key, "Restored policy, internal key, or address differs from the saved wallet. Check the pinned root key, module, and backup; do not send funds.");
      acceptWallet(record, derived);
    } catch (error) { clearWallet(); throw error; }
  }

  function clientData(bytes, type, challenge) {
    requireThat(bytes.length > 0 && bytes.length <= 4096, "Authenticator client data is outside the supported size limit.");
    const value = object(JSON.parse(textDecoder.decode(bytes)), "Authenticator client data");
    requireThat(!Object.hasOwn(value, "topOrigin"), "Cross-origin topOrigin context is not supported.");
    requireThat(value.type === type && value.challenge === base64url(challenge) && value.origin === state.config.origin && (value.crossOrigin === undefined || value.crossOrigin === false), "Authenticator ceremony, challenge, or origin does not match this request.");
  }

  async function checkAuthenticatorData(bytes, registration = false) {
    requireThat(registration ? bytes.length >= 37 : bytes.length === 37, "This example supports assertions with exactly 37 authenticator-data bytes and no extensions.");
    requireThat(equal(bytes.subarray(0, 32), await sha256(textEncoder.encode(RP_ID))), "Authenticator RP ID hash does not match this wallet’s hostname.");
    const flags = bytes[32];
    requireThat((flags & 5) === 5, "The authenticator must verify both user presence and user verification.");
    requireThat((flags & 0x22) === 0 && (!(flags & 0x10) || (flags & 8)), "Authenticator flags are invalid or unsupported.");
    if (!registration) requireThat((flags & 0xc0) === 0, "Authenticator extensions or attestation data are not supported for spending.");
  }

  async function enroll() {
    requireThat(!hasMetadata(), "Export and explicitly forget the retained wallet before enrolling a different one.");
    requireThat(typeof PublicKeyCredential !== "undefined" && navigator.credentials?.create, "Passkey enrollment requires a browser supporting WebAuthn.");
    const leaf = await recoveryLeaf(setupRecoveryKeys());
    state.controller.signal.throwIfAborted();
    await checkConfiguration();
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({ publicKey: {
      rp: { id: RP_ID, name: "Sapio passkey wallet" },
      user: { id: userId, name: `sapio-${base64url(userId).slice(0, 12)}`, displayName: "Sapio passkey wallet" },
      challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      attestation: "none", timeout: 60000,
    }, signal: state.controller.signal });
    requireThat(credential?.type === "public-key", "The authenticator did not create a public-key credential.");
    const response = credential.response;
    requireThat(typeof response.getPublicKey === "function" && typeof response.getPublicKeyAlgorithm === "function" && typeof response.getAuthenticatorData === "function", "This browser cannot expose the ES256 public key. Use a current browser supporting WebAuthn getPublicKey; no substitute credential is created.");
    requireThat(response.getPublicKeyAlgorithm() === -7, "The authenticator did not create an ES256 passkey.");
    clientData(new Uint8Array(response.clientDataJSON), "webauthn.create", challenge);
    await checkAuthenticatorData(new Uint8Array(response.getAuthenticatorData()), true);
    const spki = response.getPublicKey();
    requireThat(spki !== null, "The browser did not supply the passkey’s public key.");
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const point = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    requireThat(point.length === 65 && point[0] === 4, "Unexpected ES256 public-key encoding.");
    const publicKey = hex(concat(Uint8Array.of(2 | (point[64] & 1)), point.subarray(1, 33)));
    const credentialId = base64url(new Uint8Array(credential.rawId));
    decodeCredentialId(credentialId);
    const derived = await deriveWallet(publicKey, leaf.public_keys, leaf);
    acceptWallet(metadata(publicKey, credentialId, derived), derived);
    setStatus("Passkey and 2-of-2 recovery wallet enrolled. Export public metadata and separately back up both recovery keys. The form starts with synthetic funding only.");
  }

  function autofillDemo() {
    invalidate();
    $("funding-mode").value = "synthetic";
    $("funding-txid").value = state.wallet.synthetic_funding.txid;
    $("funding-vout").value = String(state.wallet.synthetic_funding.vout);
    $("funding-value").value = String(state.wallet.synthetic_funding.value_sats);
    $("recipient").value = state.config.default_recipient;
    $("amount").value = "50000";
    $("fee").value = "1000";
    updateFundingMode();
  }

  function updateFundingMode() {
    const synthetic = $("funding-mode").value === "synthetic";
    for (const id of ["funding-txid", "funding-vout", "funding-value"]) $(id).readOnly = synthetic;
    $("autofill").hidden = !synthetic;
    $("funding-warning").textContent = synthetic
      ? "Synthetic UTXO: no on-chain funds. The demo recipient is a fixture, not your wallet."
      : "Manual mode: supply an existing UTXO at this wallet’s exact address and verify its value independently. No chain lookup is performed. This example is not production custody.";
  }

  function updateSpendPath() {
    const recovery = $("spend-path").value === "recovery";
    $("path-warning").textContent = recovery
      ? "Recovery is local after the static assets and pinned configuration are loaded. It uses both enrolled Bitcoin private keys, with no network request, passkey prompt, enclave participation, or timelock."
      : "Normal spending uses the original passkey and the live enclave through the configured HTTPS signing transport. The two-key recovery tree remains committed to the same address.";
    if (recovery) $("recovery-secrets").open = true;
  }

  function readDraft() {
    requireThat(state.wallet && state.record, "Enroll or restore a wallet first.");
    const path = $("spend-path").value;
    requireThat(path === "passkey" || path === "recovery", "Choose a supported authorization path.");
    const txid = $("funding-txid").value.trim().toLowerCase();
    unhex(txid, "Funding transaction ID", 32);
    const funding = { txid, vout: integerField("funding-vout", "Output index", 0xffffffff, true), value_sats: integerField("funding-value", "UTXO value", MAX_SATS) };
    const recipient = witnessAddress($("recipient").value.trim(), state.config.network);
    const amount = integerField("amount", "Recipient amount", MAX_SATS);
    const fee = integerField("fee", "Miner fee", MAX_SATS);
    requireThat(amount <= funding.value_sats && fee <= funding.value_sats - amount, "Recipient amount plus fee exceeds the entered UTXO value.");
    const mode = $("funding-mode").value;
    requireThat(mode === "synthetic" || mode === "manual", "Choose a supported funding mode.");
    if (mode === "synthetic") requireThat(funding.txid === state.wallet.synthetic_funding.txid && funding.vout === 0 && funding.value_sats === 100000, "Synthetic funding fields do not match the demo. Reset the demo or explicitly switch to manual mode.");
    return { path, mode, funding, recipient: recipient.address, recipientScript: recipient.script, amount_sats: amount, fee_sats: fee, change_sats: funding.value_sats - amount - fee };
  }

  function sameDraft(a, b) {
    return a.path === b.path && a.mode === b.mode && a.recipient === b.recipient && a.amount_sats === b.amount_sats && a.fee_sats === b.fee_sats && a.funding.txid === b.funding.txid && a.funding.vout === b.funding.vout && a.funding.value_sats === b.funding.value_sats;
  }

  async function validateProposal(proposal, draft) {
    requireThat(proposal.address === state.record.address && proposal.program_id === state.record.program_id, "Prepared address or program differs from this wallet.");
    requireThat(equal(unhex(proposal.parameters, "Prepared policy", undefined, 4096), state.parameters), "Prepared policy differs from the locally encoded wallet policy.");
    const bytes = unhex(proposal.view, "Raw v2 view");
    const view = parseView(bytes);
    requireThat(equal(view.internalKey, unhex(state.record.internal_key, "Saved Taproot internal key", 32)), "Prepared internal key differs from the saved wallet.");
    const recovery = state.recovery;
    checkRecoveryDescriptor(proposal.recovery, recovery, draft.path === "recovery");
    requireThat(view.version === 2 && view.locktime === 0 && view.inputs[0].sequence === 0xfffffffd, "Prepared transaction has unexpected version, locktime, or sequence.");
    const expectedOutpoint = concat(unhex(draft.funding.txid, "Funding transaction ID", 32).reverse(), u32(draft.funding.vout));
    const walletScript = witnessAddress(state.record.address, state.config.network).script;
    requireThat(equal(view.inputs[0].outpoint, expectedOutpoint) && view.inputs[0].value === draft.funding.value_sats && equal(view.inputs[0].prevoutScript, walletScript), "Prepared input differs from the entered outpoint, value, or wallet script.");
    requireThat(view.outputs.length === (draft.change_sats > 0 ? 2 : 1), "Prepared transaction has unexpected outputs.");
    requireThat(view.outputs[0].value === draft.amount_sats && equal(view.outputs[0].script, draft.recipientScript), "Prepared recipient amount or script differs from the entered address.");
    if (draft.change_sats > 0) requireThat(view.outputs[1].value === draft.change_sats && equal(view.outputs[1].script, walletScript), "Prepared change does not return the exact remaining amount to this wallet.");
    requireThat(view.inputs[0].value - view.outputs.reduce((sum, output) => sum + output.value, 0) === draft.fee_sats, "Prepared miner fee differs from the entered fee.");
    let challenge;
    let sighash;
    if (draft.path === "recovery") {
      sighash = await recoverySighash(view, recovery.leaf_hash);
      requireThat(equal(sighash, unhex(proposal.recovery.sighash, "Wallet recovery sighash", 32)), "Wallet recovery digest differs from the independently computed BIP341 SIGHASH_ALL script-spend commitment.");
    } else {
      const nonce = unhex(proposal.nonce, "Preparation nonce", 32);
      challenge = await sha256(concat(textEncoder.encode("sapio-passkey/v2\0"), await sha256(state.parameters), await sha256(bytes), nonce));
      requireThat(equal(challenge, unhex(proposal.challenge, "Passkey challenge", 32)), "Wallet challenge differs from the independently computed transaction commitment.");
    }
    const unsignedTransaction = serializeTransaction(view);
    const txid = await transactionId(unsignedTransaction);
    const summary = object(proposal.summary, "Transaction summary");
    const funding = object(summary.funding, "Summary funding");
    requireThat(funding.txid === draft.funding.txid && funding.vout === draft.funding.vout && funding.value_sats === draft.funding.value_sats && summary.recipient === draft.recipient && summary.amount_sats === draft.amount_sats && summary.fee_sats === draft.fee_sats && summary.change_sats === draft.change_sats && summary.network === state.config.network && summary.txid === txid, "Wallet summary differs from the independently checked transaction.");
    requireThat(summary.change_address === state.record.address, "Summary change address does not match this wallet.");
    const prepared = { proposal, draft, view, recovery, challenge, sighash, unsignedTransaction, txid, revision: state.revision };
    checkPsbt(proposal.psbt, prepared);
    return prepared;
  }

  const formatSats = (value) => `${value.toLocaleString()} sats`;

  function showReview(prepared) {
    const draft = prepared.draft;
    const values = {
      "review-mode": draft.mode === "synthetic" ? "SYNTHETIC DEMO — this input does not exist on-chain; no real funds are being spent." : "MANUAL UTXO — verify the funding outpoint and its value against your own node before authorizing.",
      "review-network": state.config.network,
      "review-funding": `${draft.funding.txid}:${draft.funding.vout}`,
      "review-value": formatSats(draft.funding.value_sats),
      "review-recipient": draft.recipient,
      "review-amount": formatSats(draft.amount_sats),
      "review-fee": formatSats(draft.fee_sats),
      "review-change": formatSats(draft.change_sats),
      "review-change-address": draft.change_sats > 0 ? state.record.address : "No change output",
      "review-txid": prepared.txid,
    };
    for (const [id, value] of Object.entries(values)) $(id).textContent = value;
    const recovery = draft.path === "recovery";
    $("review-heading").textContent = recovery ? "Review before two-key recovery" : "Review before using your passkey";
    $("review-verification").textContent = recovery
      ? "The browser independently checked the recovery tree, raw transaction, PSBT, summary, and BIP341 SIGHASH_ALL script-spend digest. Editing any transaction field discards this review."
      : "The browser independently checked the committed recovery tree, raw transaction, PSBT, summary, and passkey challenge. Editing any transaction field discards this review.";
    $("review-authorization").textContent = recovery
      ? "Both matching private keys are required in the temporary fields above. Approval creates a local MuSig2 signature, without the passkey or enclave, and clears both fields even if signing fails. Check your separate backups first."
      : "Your authenticator verifies you—not the Bitcoin address on this page. Check the recipient, fee, and change now. Any temporary recovery-key fields will also be cleared on this signing attempt.";
    $("approve").textContent = recovery ? "Approve with BOTH recovery keys & sign locally" : "Approve with passkey & sign";
    $("review").hidden = false;
    $("review-heading").focus();
  }

  async function prepareSpend() {
    invalidate();
    const draft = readDraft();
    checkConfiguration();
    const body = { public_key: state.record.public_key, recovery_keys: state.record.recovery_keys, funding: draft.funding, recipient: draft.recipient, amount_sats: draft.amount_sats, fee_sats: draft.fee_sats, path: draft.path };
    if (draft.path === "passkey") body.nonce = hex(crypto.getRandomValues(new Uint8Array(32)));
    const proposal = await walletCall("prepare", state.context, body, state.controller.signal);
    if (draft.path === "passkey") requireThat(proposal.nonce === body.nonce, "Prepared nonce differs from the fresh browser nonce.");
    const prepared = await validateProposal(proposal, draft);
    requireThat(sameDraft(draft, readDraft()), "Transaction fields changed during preparation. Prepare again.");
    state.controller.signal.throwIfAborted();
    state.prepared = prepared;
    showReview(prepared);
    setStatus(draft.path === "recovery" ? "Recovery transaction independently checked. Review the details, supply both matching temporary private keys, then explicitly approve local signing." : "Transaction independently checked. Review the recipient, fee, and change, then explicitly approve with your passkey.");
  }

  async function approveSpend() {
    const prepared = state.prepared;
    const privateKeys = [];
    let localSignature;
    try {
      requireThat(prepared && prepared.revision === state.revision && sameDraft(prepared.draft, readDraft()), "The review was invalidated. Prepare and review the transaction again.");
      if (prepared.draft.path === "recovery") {
        // Read secrets only after explicit approval, never into persistent state or a request.
        for (const id of ["recovery-private-1", "recovery-private-2"]) privateKeys.push($(id).value.trim().toLowerCase());
      }
      clearRecoverySecrets();
      let result;
      if (prepared.draft.path === "recovery") {
        requireThat(privateKeys.length === 2 && privateKeys.every((key) => /^[0-9a-f]{64}$/.test(key)), "Enter both 32-byte recovery private keys. The temporary fields have been cleared; prepare again before retrying.");
        const publicKeys = recoveryKeys(await Promise.all(privateKeys.map((key) => recoveryPublicKey(key))));
        requireThat(publicKeys.every((key, index) => key === state.record.recovery_keys[index]), "Both recovery private keys must match the enrolled public-key pair. Nothing was signed.");
        state.controller.signal.throwIfAborted();
        setStatus("Both recovery keys match. Creating a fresh MuSig2 signature locally, without the passkey or enclave…");
        localSignature = await signRecovery(privateKeys, state.record.recovery_keys, hex(prepared.sighash));
        unhex(localSignature, "Recovery signature", 64);
        privateKeys.fill("");
        requireThat(prepared.revision === state.revision && sameDraft(prepared.draft, readDraft()), "Transaction fields changed during recovery authorization. Prepare again.");
        state.controller.signal.throwIfAborted();
        result = await walletCall("finalize_recovery", state.context, { public_key: state.record.public_key, recovery_keys: state.record.recovery_keys, psbt: prepared.proposal.psbt, signature: localSignature }, state.controller.signal);
      } else {
        requireThat(typeof PublicKeyCredential !== "undefined" && navigator.credentials?.get, "Normal spending requires WebAuthn. The enrolled two-key recovery path remains available without it.");
        await checkConfiguration();
        const credential = await navigator.credentials.get({ publicKey: {
          rpId: RP_ID, challenge: prepared.challenge,
          allowCredentials: [{ type: "public-key", id: decodeCredentialId(state.record.credential_id) }],
          userVerification: "required", timeout: 60000,
        }, signal: state.controller.signal });
        requireThat(credential?.type === "public-key" && base64url(new Uint8Array(credential.rawId)) === state.record.credential_id, "The authenticator returned a different credential.");
        const response = credential.response;
        const authenticatorData = new Uint8Array(response.authenticatorData);
        const json = new Uint8Array(response.clientDataJSON);
        clientData(json, "webauthn.get", prepared.challenge);
        await checkAuthenticatorData(authenticatorData);
        requireThat(prepared.revision === state.revision && sameDraft(prepared.draft, readDraft()), "Transaction fields changed during authorization. Prepare again.");
        state.controller.signal.throwIfAborted();
        const request = await walletCall("request", state.context, { public_key: state.record.public_key, recovery_keys: state.record.recovery_keys, psbt: prepared.proposal.psbt, nonce: prepared.proposal.nonce, authenticator_data: hex(authenticatorData), client_data_json: hex(json), signature: hex(new Uint8Array(response.signature)) }, state.controller.signal);
        setStatus("Passkey approved. Sending only the policy-signing envelope to the live enclave through the configured HTTPS transport…");
        const oracleResponse = await requestSignature(request);
        setStatus("Verifying the enclave response and finalizing the exact reviewed transaction locally in WASM…");
        result = await walletCall("finalize_passkey", state.context, { request, response: oracleResponse }, state.controller.signal);
      }
      const signedTransaction = parseSignedTransaction(result.transaction_hex, prepared, localSignature);
      const unsigned = serializeTransaction(signedTransaction);
      requireThat(equal(unsigned, prepared.unsignedTransaction) && result.txid === prepared.txid && result.txid === await transactionId(unsigned), "Signed transaction differs from the reviewed transaction. Nothing was exported or broadcast.");
      requireThat(result.fee_sats === prepared.draft.fee_sats, "Signed transaction fee differs from the review.");
      checkPsbt(result.signed_psbt, prepared, signedTransaction);
      requireThat(prepared.revision === state.revision && sameDraft(prepared.draft, readDraft()), "Transaction review changed before signing completed. Nothing was exported.");
      state.controller.signal.throwIfAborted();
      state.signed = { ...result, mode: prepared.draft.mode };
      $("result-txid").value = result.txid;
      $("transaction-hex").value = result.transaction_hex;
      $("signed-psbt").value = result.signed_psbt;
      $("result-note").textContent = prepared.draft.mode === "synthetic"
        ? "Synthetic demo complete. This signature is real, but its funding input is fabricated; this transaction cannot spend on-chain funds. The exports are for inspection only."
        : "Export only. This page has not broadcast anything. Independently verify the UTXO, transaction, fee, and signatures before using another tool to broadcast.";
      $("result").hidden = false;
      $("result-heading").focus();
      setStatus(prepared.draft.path === "recovery" ? "Two-key recovery signature and exact three-item script witness checked. No passkey or enclave was used. Nothing was broadcast." : "Signed transaction verified against your review. Nothing has been broadcast.");
    } finally {
      privateKeys.fill("");
      clearRecoverySecrets();
      // Every attempt requires a new review and fresh authorization/nonces.
      state.prepared = null;
      $("review").hidden = true;
    }
  }

  function renderControls() {
    const retained = hasMetadata();
    let setupReady = false;
    try { setupRecoveryKeys(); setupReady = true; } catch { /* Point validation runs before enrollment. */ }
    $("setup-fields").disabled = state.busy || !state.config || retained;
    $("secret-fields").disabled = state.busy;
    $("enroll").disabled = state.busy || !state.config || retained || !setupReady;
    $("generate-recovery").disabled = state.busy || !state.config || retained;
    $("restore-file").disabled = state.busy || !state.config || retained;
    $("reconnect").hidden = !retained || !!state.wallet;
    $("reconnect").disabled = state.busy || !retained;
    $("export-metadata").disabled = state.busy || !retained;
    $("forget").disabled = state.busy || !retained;
    $("spend-fields").disabled = state.busy || !state.wallet;
    $("prepare").disabled = state.busy || !state.wallet;
    $("approve").disabled = state.busy || !state.prepared;
    $("export-transaction").disabled = state.busy || !state.signed;
    $("export-psbt").disabled = state.busy || !state.signed;
    $("cancel").hidden = !state.busy;
    $("cancel").disabled = state.controller?.signal.aborted ?? false;
    $("spend-form").setAttribute("aria-busy", String(state.busy));
  }

  function setStatus(message) { $("status").textContent = message; }

  function explainError(error) {
    if (error?.name === "AbortError") return state.signRequestSent ? "Cancelled locally. A request already sent to the enclave signing transport may have completed, but nothing was broadcast. Temporary keys are cleared; prepare again for fresh authorization." : "Operation cancelled. Temporary recovery keys are cleared. Prepare again if you want to authorize a spend.";
    if (error?.name === "NotAllowedError") return "Passkey request was cancelled, timed out, or user verification was unavailable. Unlock the original authenticator and retry, or use the enrolled two-key recovery path with both private keys.";
    if (error?.name === "SecurityError") return `WebAuthn rejected this origin. Open exactly ${ORIGIN} in a top-level browser tab, using the original wallet hostname and port.`;
    if (error?.name === "NotSupportedError") return "The browser or authenticator does not support the required ES256 passkey or user verification. Use a supported authenticator for normal spending, or both enrolled Bitcoin keys for recovery.";
    if (error instanceof TypeError && /fetch|network|load failed/i.test(error.message)) return state.signRequestSent
      ? "Cannot reach the configured enclave signing transport. Nothing was broadcast. Two-key recovery remains local after the static assets are loaded."
      : "Could not load a required static wallet asset or configuration. Serve all wallet assets together at this exact origin and reload. Public metadata remains available for export.";
    return error instanceof Error ? error.message : "The operation failed. Nothing was broadcast.";
  }

  async function run(label, operation) {
    if (state.busy) return;
    state.busy = true;
    state.controller = new AbortController();
    state.signRequestSent = false;
    $("error").hidden = true;
    $("error").textContent = "";
    setStatus(label);
    renderControls();
    try { await operation(); }
    catch (error) {
      $("error").textContent = explainError(error);
      $("error").hidden = false;
      setStatus("Operation stopped. Resolve the message above before continuing.");
    } finally {
      state.busy = false;
      state.controller = null;
      renderControls();
    }
  }

  function download(name, content, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function freeze(value) {
    if (value !== null && typeof value === "object") {
      for (const item of Object.values(value)) freeze(item);
      Object.freeze(value);
    }
    return value;
  }

  async function loadConfiguration() {
    // Pin this exact public identity for the entire page lifetime, including
    // retry/restore and recovery. Only an explicit reload reads the file again.
    configurationPromise ??= (async () => {
      const response = await fetch(new URL("./wallet-config.json", import.meta.url), {
        headers: { Accept: "application/json" }, credentials: "omit", mode: "same-origin",
        cache: "no-store", redirect: "error", signal: state.controller.signal,
      });
      const config = await readJson(response, "Static wallet configuration");
      const fields = ["version", "identity", "sign_url", "allow_local_dev"];
      requireThat(Object.keys(config).length === fields.length && fields.every((field) => Object.hasOwn(config, field))
        && config.version === 1 && typeof config.allow_local_dev === "boolean", "Use an operator-supplied version-1 static wallet configuration with a verified public identity.");
      object(config.identity, "Pinned public identity");
      requireThat(location.protocol === "https:" || (config.allow_local_dev && location.protocol === "http:" && RP_ID === "localhost"), "This wallet requires HTTPS. HTTP is allowed only on localhost with an explicit local-development configuration.");
      requireThat(typeof config.sign_url === "string" && config.sign_url.length > 0, "Static configuration must name the enclave HTTPS signing endpoint.");
      const signUrl = new URL(config.sign_url, new URL("./", import.meta.url));
      requireThat(!signUrl.username && !signUrl.password && !signUrl.search && !signUrl.hash
        && signUrl.pathname.endsWith("/api/sign")
        && (signUrl.protocol === "https:" || (config.allow_local_dev && signUrl.protocol === "http:" && signUrl.hostname === "localhost")),
        "The configured signing URL must be an HTTPS /api/sign endpoint, without credentials, query, or fragment. Only explicit localhost development permits HTTP.");
      const context = freeze({ identity: config.identity, origin: ORIGIN, rp_id: RP_ID, allow_local_dev: config.allow_local_dev });
      const validated = freeze(validateConfig(await walletCall("configure", context, {}, state.controller.signal)));
      state.controller.signal.throwIfAborted();
      state.context = context;
      state.config = validated;
      state.signUrl = signUrl.href;
    })();
    await configurationPromise;
    checkConfiguration();
    $("network-badge").textContent = `${state.config.network} · static wallet`;
    $("environment-badge").textContent = state.config.local_dev ? "Local fixture · no hardware TEE assurance" : "Pinned enclave identity · attestation verified separately";
    $("identity-origin").textContent = `${state.config.origin} / ${state.config.rp_id}`;
    $("identity-genesis").textContent = state.config.genesis_hash;
    $("identity-root").textContent = state.config.xpub;
    $("identity-module").textContent = `${state.config.module_sha256} (${state.config.module_bytes.toLocaleString()} bytes)`;
  }

  $("generate-recovery").addEventListener("click", () => {
    if (state.busy || hasMetadata() || !confirm("Generate BOTH recovery private keys in this browser? This is a software demonstration, not independent signers or hardware protection. Existing setup fields will be replaced. Back up each private key separately now; signing, cancellation, forget, or closing this page loses the temporary copies.")) return;
    run("Generating two temporary software-demo recovery keys locally…", async () => {
      const generated = [];
      clearRecoverySecrets();
      try {
        for (let index = 0; index < 2; index++) {
          state.controller.signal.throwIfAborted();
          generated.push(await generateRecoveryKey());
        }
        recoveryKeys(generated.map((key) => key.public_key));
        state.controller.signal.throwIfAborted();
        generated.forEach((key, index) => {
          $(`recovery-public-${index + 1}`).value = key.public_key;
          $(`recovery-private-${index + 1}`).value = key.private_key;
        });
        $("recovery-secrets").open = true;
        setStatus("Two demo keys generated only in temporary fields. Show them and make separate backups now. They are NOT part of exported metadata and will be cleared on any signing attempt.");
      } catch (error) {
        clearRecoverySecrets();
        throw error;
      } finally {
        for (const key of generated) key.private_key = "";
      }
    });
  });
  $("setup-fields").addEventListener("input", () => { if (!state.busy) renderControls(); });
  $("show-recovery-secrets").addEventListener("change", () => {
    for (const id of ["recovery-private-1", "recovery-private-2"]) $(id).type = $("show-recovery-secrets").checked ? "text" : "password";
  });
  $("reconnect").addEventListener("click", () => run("Rechecking retained metadata without replacing the wallet…", async () => {
    const stored = state.retainedMetadata ?? state.legacyMetadata;
    requireThat(state.record || stored !== null, "There is no retained metadata to restore.");
    requireThat(state.record || stored.length <= 16384, "Retained metadata is too large. Export the original file for inspection.");
    await loadConfiguration();
    await restoreRecord(state.record ?? JSON.parse(stored));
    setStatus("Retained wallet restored. Use its original passkey and enclave, or both recovery private keys.");
  }));
  $("enroll").addEventListener("click", () => run("Waiting for a new ES256 passkey with user verification…", enroll));
  $("restore-file").addEventListener("change", () => {
    if (state.busy || hasMetadata()) return;
    const file = $("restore-file").files[0];
    $("restore-file").value = "";
    if (!file) return;
    run("Checking public metadata against the pinned static identity and policy…", async () => {
      requireThat(file.size > 0 && file.size <= 16384, "Public metadata backup must be a JSON file smaller than 16 KiB.");
      state.retainedMetadata = await file.text();
      await checkConfiguration();
      await restoreRecord(JSON.parse(state.retainedMetadata));
      setStatus("Wallet metadata restored and checked. Use the original passkey and enclave, or both matching recovery private keys without the passkey.");
    });
  });
  $("export-metadata").addEventListener("click", () => {
    if (state.record) download(`sapio-passkey-${state.record.program_id.slice(0, 12)}.json`, JSON.stringify(state.record, null, 2) + "\n", "application/json");
    else if (state.retainedMetadata !== null) download("sapio-passkey-retained-metadata.json", state.retainedMetadata, "application/json");
    if (state.legacyMetadata !== null) download("sapio-passkey-legacy-v1-metadata.json", state.legacyMetadata, "application/json");
  });
  $("forget").addEventListener("click", () => {
    if (!state.busy && confirm("Forget this browser’s retained public metadata and clear BOTH temporary recovery private-key fields? Export metadata and back up private keys separately first. This does not delete the passkey, recover funds, or change any wallet’s spending policy.")) {
      clearWallet(true);
      setStatus("Public metadata forgotten. Import your backup to use the same wallet again; creating a new passkey creates a different wallet.");
    }
  });
  $("spend-form").addEventListener("input", () => {
    if (!state.busy) { invalidate(); setStatus("Transaction details changed. Prepare and review again before authorizing."); }
  });
  $("spend-path").addEventListener("change", () => {
    if (state.busy || !state.wallet) return;
    invalidate();
    updateSpendPath();
  });
  $("funding-mode").addEventListener("change", () => {
    if (state.busy || !state.wallet) return;
    invalidate();
    if ($("funding-mode").value === "synthetic") autofillDemo();
    else {
      for (const id of ["funding-txid", "funding-vout", "funding-value", "recipient", "amount", "fee"]) $(id).value = "";
      updateFundingMode();
    }
  });
  $("autofill").addEventListener("click", () => { if (!state.busy && state.wallet) { autofillDemo(); setStatus("Synthetic demo reset. The funding input and recipient are fixtures, not real funds."); } });
  $("spend-form").addEventListener("submit", (event) => { event.preventDefault(); run("Building and independently checking the proposed transaction…", prepareSpend); });
  $("approve").addEventListener("click", () => run(state.prepared?.draft.path === "recovery" ? "Checking both recovery keys for explicitly approved local signing…" : "Waiting for your passkey’s user-verification prompt…", approveSpend));
  $("cancel").addEventListener("click", () => { state.controller?.abort(); clearRecoverySecrets(); invalidate(); setStatus("Cancelling locally; temporary recovery keys are cleared and nothing will be broadcast…"); renderControls(); });
  $("export-transaction").addEventListener("click", () => { if (state.signed) download(`${state.signed.txid}.hex`, state.signed.transaction_hex + "\n", "text/plain"); });
  $("export-psbt").addEventListener("click", () => { if (state.signed) download(`${state.signed.txid}.psbt`, decodeBase64(state.signed.signed_psbt, "Signed PSBT"), "application/octet-stream"); });
  window.addEventListener("pagehide", clearRecoverySecrets);

  run("Loading the pinned static wallet configuration…", async () => {
    try {
      state.retainedMetadata = localStorage.getItem(STORAGE_KEY);
      state.legacyMetadata = localStorage.getItem(LEGACY_STORAGE_KEY);
    } catch { /* Enrollment and explicit export/import still work without storage. */ }
    requireThat((location.protocol === "https:" || (location.protocol === "http:" && RP_ID === "localhost"))
      && window.isSecureContext && window.top === window.self, `Open ${ORIGIN} as a top-level secure page. HTTPS is required except explicitly configured localhost development.`);
    requireThat(crypto.subtle && crypto.getRandomValues && typeof WebAssembly !== "undefined", "This browser requires WebCrypto and WebAssembly for independent transaction checks and local recovery signing.");
    await loadConfiguration();
    const stored = state.retainedMetadata ?? state.legacyMetadata;
    if (stored !== null) {
      try {
        requireThat(stored.length <= 16384, "Saved public metadata exceeds the size limit. It is retained for export.");
        await restoreRecord(JSON.parse(stored));
      } catch (error) { clearWallet(); throw error; }
      setStatus("Saved wallet metadata and recovery tree verified against the pinned root, module, network, policy, and address. Synthetic demo fields are ready.");
    } else setStatus("Static wallet ready. Enter two Bitcoin recovery public keys before enrolling, or import version-2 public metadata. Normal signing uses the live enclave; recovery stays local. Start with synthetic funding only.");
  });
})();
