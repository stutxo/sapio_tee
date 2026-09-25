"use strict";

const INPUT_CAPACITY = 1048576;
const OUTPUT_CAPACITY = 1048576;
const MAX_MEMORY = 33554432;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
let compiledModule;

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

async function module(signal) {
  if (!compiledModule) {
    compiledModule = (async () => {
      const response = await fetch(new URL("./wallet.wasm", import.meta.url), {
        credentials: "omit", mode: "same-origin", redirect: "error", signal,
      });
      requireThat(response.ok, "Could not load the static wallet WASM module.");
      const compiled = await WebAssembly.compile(await response.arrayBuffer());
      requireThat(WebAssembly.Module.imports(compiled).length === 0, "Wallet WASM must not import any host functions or memory.");
      return compiled;
    })().catch((error) => {
      compiledModule = undefined;
      throw error;
    });
  }
  return compiledModule;
}

function buffers(api) {
  requireThat(api.memory instanceof WebAssembly.Memory && api.memory.buffer instanceof ArrayBuffer, "Wallet WASM has no unshared linear memory.");
  requireThat(api.wallet_input_capacity() === INPUT_CAPACITY && api.wallet_output_capacity() === OUTPUT_CAPACITY, "Wallet WASM has incompatible buffer limits.");
  const input = api.wallet_input();
  const output = api.wallet_output();
  const memory = new Uint8Array(api.memory.buffer);
  requireThat(memory.length <= MAX_MEMORY && Number.isInteger(input) && Number.isInteger(output)
    && input >= 0 && output >= 0 && input + INPUT_CAPACITY <= memory.length
    && output + OUTPUT_CAPACITY <= memory.length
    && (input + INPUT_CAPACITY <= output || output + OUTPUT_CAPACITY <= input), "Wallet WASM buffers are out of bounds.");
  return { input, output, memory };
}

// Only the compiled code is shared. No operation can reuse another instance's
// state. This module accepts public wallet data, never recovery private keys.
export async function walletCall(operation, context, body = {}, signal) {
  signal?.throwIfAborted();
  requireThat(typeof operation === "string" && context !== null && typeof context === "object"
    && !Array.isArray(context) && body !== null && typeof body === "object" && !Array.isArray(body), "Invalid wallet WASM request.");
  const input = encoder.encode(JSON.stringify({ operation, context, body }));
  requireThat(input.length > 0 && input.length <= INPUT_CAPACITY, "Wallet operation exceeds its input limit.");
  let instance;
  try {
    const compiled = await module(signal);
    signal?.throwIfAborted();
    instance = await WebAssembly.instantiate(compiled, {});
    signal?.throwIfAborted();
    const api = instance.exports;
    for (const name of ["wallet_input", "wallet_input_capacity", "wallet_output", "wallet_output_capacity", "wallet_execute"]) {
      requireThat(typeof api[name] === "function", "Wallet WASM has an incompatible ABI.");
    }
    const before = buffers(api);
    before.memory.set(input, before.input);
    const length = api.wallet_execute(input.length);
    signal?.throwIfAborted();
    const after = buffers(api);
    requireThat(before.input === after.input && before.output === after.output
      && Number.isInteger(length) && length > 0 && length <= OUTPUT_CAPACITY, "Wallet WASM returned an invalid result length or moved its buffers.");
    const result = JSON.parse(decoder.decode(after.memory.subarray(after.output, after.output + length)));
    requireThat(result !== null && typeof result === "object" && !Array.isArray(result)
      && Object.keys(result).length === 1, "Wallet WASM returned an invalid result envelope.");
    if (Object.hasOwn(result, "error")) {
      requireThat(typeof result.error === "string" && result.error.length > 0, "Wallet WASM returned an invalid error.");
      throw new Error(result.error);
    }
    requireThat(Object.hasOwn(result, "ok"), "Wallet WASM returned no result.");
    return result.ok;
  } finally {
    input.fill(0);
    if (instance?.exports.memory instanceof WebAssembly.Memory) {
      try { new Uint8Array(instance.exports.memory.buffer).fill(0); }
      catch { /* Never reuse a trapped or detached instance. */ }
    }
  }
}
