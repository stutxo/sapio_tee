"use strict";

// This software-key demo is NOT distributed signing or hardware-backed custody.
// Only the compiled module is cached. Every operation owns a fresh instance.
const INPUT_CAPACITY = 226;
const OUTPUT_CAPACITY = 64;
const MAX_MEMORY = 4 * 1024 * 1024;
let compiledModule;

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function unhex(value, label, length) {
  requireThat(typeof value === "string" && value.length === length * 2 && /^[0-9a-fA-F]+$/.test(value), `${label} must be exactly ${length} bytes of hex.`);
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function pair(value, label) {
  requireThat(Array.isArray(value) && value.length === 2, `${label} must contain exactly two keys.`);
  return value;
}

function publicKey(value, label) {
  const bytes = unhex(value, label, 33);
  requireThat(bytes[0] === 2 || bytes[0] === 3, `${label} must be a compressed SEC1 secp256k1 public key.`);
  return bytes;
}

async function module() {
  if (!compiledModule) {
    compiledModule = (async () => {
      const response = await fetch(new URL("./recovery.wasm", import.meta.url), { credentials: "omit", mode: "same-origin", redirect: "error" });
      requireThat(response.ok, "Could not load the recovery cryptography module.");
      const compiled = await WebAssembly.compile(await response.arrayBuffer());
      requireThat(WebAssembly.Module.imports(compiled).length === 0, "Recovery WASM must not import any host functions or memory.");
      return compiled;
    })().catch((error) => {
      compiledModule = undefined;
      throw error;
    });
  }
  return compiledModule;
}

async function execute(operation, parts, outputLength) {
  let instance;
  try {
    instance = await WebAssembly.instantiate(await module(), {});
    const api = instance.exports;
    requireThat(api.memory instanceof WebAssembly.Memory, "Recovery module has no linear memory.");
    for (const name of ["recovery_input", "recovery_output", "recovery_input_capacity", "recovery_output_capacity", "recovery_execute"]) {
      requireThat(typeof api[name] === "function", "Recovery module has an incompatible ABI.");
    }
    requireThat(api.recovery_input_capacity() === INPUT_CAPACITY && api.recovery_output_capacity() === OUTPUT_CAPACITY, "Recovery module has incompatible buffer limits.");
    const inputLength = parts.reduce((size, part) => size + part.length, 0);
    requireThat(inputLength <= INPUT_CAPACITY && outputLength <= OUTPUT_CAPACITY, "Recovery operation exceeds its buffer limits.");
    const input = api.recovery_input();
    const output = api.recovery_output();
    const memory = new Uint8Array(api.memory.buffer);
    requireThat(memory.length <= MAX_MEMORY && Number.isInteger(input) && Number.isInteger(output)
      && input >= 0 && output >= 0 && input + INPUT_CAPACITY <= memory.length
      && output + OUTPUT_CAPACITY <= memory.length
      && (input + INPUT_CAPACITY <= output || output + OUTPUT_CAPACITY <= input), "Recovery module buffers are out of bounds.");
    let offset = input;
    for (const part of parts) {
      memory.set(part, offset);
      offset += part.length;
    }
    const length = api.recovery_execute(operation, inputLength);
    if (length === 0) return null;
    requireThat(length === outputLength && api.memory.buffer.byteLength <= MAX_MEMORY, "Recovery module returned an invalid result.");
    // Copy only public output before destroying the instance's entire memory.
    return new Uint8Array(api.memory.buffer, output, length).slice();
  } finally {
    if (instance?.exports.memory instanceof WebAssembly.Memory) {
      try {
        new Uint8Array(instance.exports.memory.buffer).fill(0);
      } catch {
        // Best effort even on a trapped/detached instance; never reuse it.
      }
    }
  }
}

export async function recoveryPublicKey(secretHex) {
  let secret;
  try {
    secret = unhex(secretHex, "Recovery private key", 32);
    const result = await execute(1, [secret], 33);
    requireThat(result, "Recovery private key is zero or outside the secp256k1 scalar range.");
    return hex(result);
  } finally {
    secret?.fill(0);
    // JS strings (including secretHex) cannot be reliably erased.
  }
}

export async function aggregateRecoveryKeys(publicKeys) {
  const keys = pair(publicKeys, "Recovery public keys");
  const first = publicKey(keys[0], "First recovery public key");
  const second = publicKey(keys[1], "Second recovery public key");
  const result = await execute(2, [first, second], 32);
  requireThat(result, "Recovery keys must be valid, distinct secp256k1 points with different x coordinates.");
  return hex(result);
}

export async function signRecovery(privateKeys, expectedPublicKeys, messageHex) {
  const buffers = [];
  try {
    pair(privateKeys, "Recovery private keys");
    pair(expectedPublicKeys, "Expected recovery public keys");
    for (let i = 0; i < 2; i++) buffers.push(unhex(privateKeys[i], "Recovery private key", 32));
    for (let i = 0; i < 2; i++) buffers.push(publicKey(expectedPublicKeys[i], "Expected recovery public key"));
    buffers.push(unhex(messageHex, "Recovery message", 32));
    const randomness = new Uint8Array(64);
    buffers.push(randomness);
    crypto.getRandomValues(randomness);
    const result = await execute(3, buffers, 64);
    requireThat(result, "Recovery signing failed: both private keys must match the distinct expected public keys, and randomness must be fresh and nonzero.");
    return hex(result);
  } finally {
    for (const buffer of buffers) buffer.fill(0);
    // Immutable private-key strings remain the caller's responsibility. This
    // helper never persists, logs, transmits or returns them when signing.
  }
}

export async function generateRecoveryKey() {
  const secret = new Uint8Array(32);
  try {
    // Rejection sampling handles zero and scalars at/above the group order.
    // The bound prevents a broken randomness source from causing an endless loop.
    for (let attempt = 0; attempt < 128; attempt++) {
      crypto.getRandomValues(secret);
      const result = await execute(1, [secret], 33);
      if (result) return { public_key: hex(result), private_key: hex(secret) };
    }
    throw new Error("Could not generate a valid recovery key.");
  } finally {
    secret.fill(0);
    // This explicit demo operation alone returns an immutable private string.
  }
}

export async function tweakRecoveryOutput(internalKeyHex, tweakHex) {
  const internalKey = unhex(internalKeyHex, "Internal key", 32);
  const tweak = unhex(tweakHex, "TapTweak", 32);
  const result = await execute(4, [internalKey, tweak], 33);
  requireThat(result && result[32] <= 1, "Invalid internal key or TapTweak.");
  return { output_key: hex(result.subarray(0, 32)), parity: result[32] };
}
