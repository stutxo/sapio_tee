// Thin Groth16 protocol adapter; all curve and pairing arithmetic is upstream
// MCL. G16L must come from validated preparation before funding: decoding a
// canonical line table does not authenticate it against a source VK.
#include "codec.hpp"

#if !defined(__wasm32__)
#error "The MCL guest must be built for wasm32"
#endif

extern "C" void __wasm_call_ctors();
extern "C" __attribute__((import_module("sapio_crypto_v1"), import_name("sha256")))
int32_t sapio_sha256(uint32_t pointer, uint32_t length, uint32_t output);

namespace {

const size_t MAX_VIEW = 1048576;
const size_t MAX_ARGUMENT = 65536;
const size_t INPUT_CAPACITY = MAX_VIEW + 3 * MAX_ARGUMENT;
const char DOMAIN[] = "sapio/checkzkp/bn254/v1";
CYBOZU_ALIGN(16) uint8_t input[INPUT_CAPACITY];
size_t input_used = 0;
uint8_t initialization = 0;

bool initialize_guest()
{
    if (initialization == 0) {
        initialization = 1;
        // Upstream wasm/glue.js calls the constructors before curve init.
        // Here both occur inside a metered entrypoint, not a wasm start section
        // or an unmetered host verifier. Initialization is attempted only once.
        __wasm_call_ctors();
        if (checkzkp::initialize_curve()) initialization = 2;
    }
    return initialization == 2;
}

const uint8_t* input_slice(uint32_t pointer, uint32_t length)
{
    // Match examples/vault/guest.rs: empty slices ignore their pointer.
    if (length == 0) return input;
    const uintptr_t start = reinterpret_cast<uintptr_t>(input);
    if (pointer < start) return NULL;
    const size_t offset = pointer - start;
    if (offset > input_used || length > input_used - offset) return NULL;
    return input + offset;
}

bool validate_view(const uint8_t* bytes, size_t length)
{
    checkzkp::Reader view(bytes, length);
    uint32_t selected, inputs, outputs, script_length;
    if (!view.take(8) || !view.u32(selected) || !view.u32(inputs)
        || selected >= inputs) return false;
    for (uint32_t i = 0; i < inputs; ++i) {
        // Outpoint, sequence, prevout value, then a length-prefixed script.
        if (!view.take(48) || !view.u32(script_length)
            || !view.take(script_length)) return false;
    }
    if (!view.u32(outputs)) return false;
    for (uint32_t i = 0; i < outputs; ++i) {
        if (!view.take(8) || !view.u32(script_length)
            || !view.take(script_length)) return false;
    }
    return view.finished();
}

bool hash(const uint8_t* bytes, size_t length, uint8_t* digest)
{
    return sapio_sha256(uint32_t(reinterpret_cast<uintptr_t>(bytes)), uint32_t(length),
        uint32_t(reinterpret_cast<uintptr_t>(digest))) == 0;
}

int32_t evaluate(const uint8_t* parameters, size_t parameters_length,
    const uint8_t* view, size_t view_length, const uint8_t* witness)
{
    using namespace checkzkp;
    Reader encoded(parameters, parameters_length);
    const uint8_t* tag = encoded.take(4);
    uint32_t count;
    if (!tag || memcmp(tag, "G16L", 4) != 0 || !encoded.u32(count)
        || count == 0 || count > MAX_COEFFICIENTS
        || parameters_length != prepared_size(count)
        || !validate_view(view, view_length) || !initialize_guest()
        || count != mcl::getPrecomputedQcoeffSize()) return -1;

    mcl::Fp12 target;
    if (!read_field<FP12_BYTES>(encoded, target) || target.isZero()) return -1;
    mcl::Fp6 gamma[MAX_COEFFICIENTS], delta[MAX_COEFFICIENTS];
    for (size_t i = 0; i < count; ++i) {
        if (!read_field<FP6_BYTES>(encoded, gamma[i])) return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!read_field<FP6_BYTES>(encoded, delta[i])) return -1;
    }
    mcl::G1 folded, terms[4];
    if (!read_folded_ic(encoded, folded)) return -1;
    for (size_t i = 0; i < 4; ++i) {
        if (!read_g1(encoded, terms[i])) return -1;
    }
    // C's two scalars have already been folded into the committed IC.
    if (!encoded.take(32) || !encoded.finished()) return -1;

    Reader proof(witness, PROOF_BYTES);
    mcl::G1 a, c;
    mcl::G2 b;
    if (!read_g1(proof, a) || !read_g2(proof, b) || !read_g1(proof, c)
        || !proof.finished()) return -1;

    uint8_t transcript[sizeof(DOMAIN) - 1 + 32];
    memcpy(transcript, DOMAIN, sizeof(DOMAIN) - 1);
    uint8_t transaction_digest[32];
    if (!hash(view, view_length, transcript + sizeof(DOMAIN) - 1)
        || !hash(transcript, sizeof(transcript), transaction_digest)) return -1;
    mcl::Fr scalars[4];
    if (!read_scalar_half(transaction_digest, scalars[0])
        || !read_scalar_half(transaction_digest + 16, scalars[1])
        || !read_scalar_half(witness + PROOF_BYTES, scalars[2])
        || !read_scalar_half(witness + PROOF_BYTES + 16, scalars[3])) return -1;

    mcl::G1 ic;
    mcl::G1::mulVec(ic, terms, scalars, 4);
    mcl::G1::add(ic, ic, folded);
    mcl::G1::neg(ic, ic);
    mcl::G1::neg(c, c);
    mcl::Fp12 product, fixed;
    mcl::millerLoop(product, a, b);
    // Upstream precomputedMillerLoop2 requires non-infinity G1 arguments.
    // Only the computed IC may be infinity; omit its identity pairing using
    // the stock single-precomputed API, never a replacement pairing formula.
    if (ic.isZero()) {
        mcl::precomputedMillerLoop(fixed, c, delta);
    } else {
        mcl::precomputedMillerLoop2(fixed, ic, gamma, c, delta);
    }
    mcl::Fp12::mul(product, product, fixed);
    // A malformed committed line table can induce zero; never invert it in
    // finalExp. This is malformed input (-1), not a false equation (0).
    if (product.isZero()) return -1;
    mcl::finalExp(product, product);
    return product == target ? 1 : 0;
}

} // namespace

extern "C" uint32_t sapio_alloc_v1(uint32_t length)
{
    // Fresh instance per invocation, with no reentrant guest imports. This
    // fixed arena is disjoint from the stack, MCL's state, and its heap.
    if (length > INPUT_CAPACITY - input_used) return 0;
    uint8_t* result = input + input_used;
    input_used += length;
    return uint32_t(reinterpret_cast<uintptr_t>(result));
}

extern "C" int32_t sapio_evaluate_v1(uint32_t pp, uint32_t pl,
    uint32_t ap, uint32_t al, uint32_t vp, uint32_t vl, uint32_t wp, uint32_t wl)
{
    if (pl > MAX_ARGUMENT || al > MAX_ARGUMENT || wl > MAX_ARGUMENT || vl > MAX_VIEW) {
        return -1;
    }
    const uint8_t* program = input_slice(pp, pl);
    const uint8_t* parameters = input_slice(ap, al);
    const uint8_t* view = input_slice(vp, vl);
    const uint8_t* witness = input_slice(wp, wl);
    if (!program || !parameters || !view || !witness || pl != 0
        || wl != checkzkp::WITNESS_BYTES) return -1;
    return evaluate(parameters, al, view, vl, witness);
}
