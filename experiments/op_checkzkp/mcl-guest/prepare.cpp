// Fixed preprocessing only: this program never receives a proof or signed view.
// Run before funding, and commit the complete G16L bytes and guest module in
// the funding identity. Canonical decoding does not authenticate line tables.
#include "codec.hpp"
#include <stdio.h>

namespace {

int fail(const char* message)
{
    fprintf(stderr, "MCL preparation: %s\n", message);
    return 1;
}

} // namespace

int main(int argc, char**)
{
    using namespace checkzkp;
    if (argc != 1) return fail("expected no arguments; read raw VK || C from stdin");

    uint8_t raw[RAW_PARAMETERS_BYTES];
    if (fread(raw, 1, sizeof(raw), stdin) != sizeof(raw)) {
        return fail("source parameters must be exactly 928 bytes");
    }
    if (fgetc(stdin) != EOF || ferror(stdin)) {
        return fail("trailing bytes or input error");
    }
    if (!initialize_curve()) return fail("BN_SNARK1 initialization failed");
    const size_t count = mcl::getPrecomputedQcoeffSize();
    if (count == 0 || count > MAX_COEFFICIENTS) {
        return fail("incompatible MCL line coefficient count");
    }

    Reader source(raw, RAW_VK_BYTES);
    mcl::G1 alpha, ic[7];
    mcl::G2 beta, gamma, delta;
    if (!read_g1(source, alpha)) return fail("invalid source alpha");
    if (!read_g2(source, beta)) return fail("invalid source beta");
    if (!read_g2(source, gamma)) return fail("invalid source gamma");
    if (!read_g2(source, delta)) return fail("invalid source delta");
    for (size_t i = 0; i < 7; ++i) {
        if (!read_g1(source, ic[i])) return fail("invalid source IC point");
    }
    if (!source.finished()) return fail("invalid source VK length");

    // Validate every original point before any folding can discard it.
    mcl::Fr commitment[2];
    if (!read_scalar_half(raw + RAW_VK_BYTES, commitment[0])
        || !read_scalar_half(raw + RAW_VK_BYTES + 16, commitment[1])) {
        return fail("invalid commitment scalar");
    }
    mcl::G1 folded;
    mcl::G1::mulVec(folded, ic + 1, commitment, 2);
    mcl::G1::add(folded, folded, ic[0]);

    mcl::Fp12 target;
    mcl::pairing(target, alpha, beta);
    if (target.isZero()) return fail("zero pairing target");
    mcl::Fp6 lines[MAX_COEFFICIENTS];
    uint8_t encoded[MAX_PREPARED_BYTES];
    const size_t output_size = prepared_size(count);
    Writer output(encoded, output_size);
    if (!output.append("G16L", 4) || !output.u32(uint32_t(count))
        || !write_field<FP12_BYTES>(output, target)) {
        return fail("target serialization failed");
    }
    // Positive gamma and delta; the guest negates the corresponding G1 inputs.
    mcl::precomputeG2(lines, gamma);
    for (size_t i = 0; i < count; ++i) {
        if (!write_field<FP6_BYTES>(output, lines[i])) {
            return fail("gamma line serialization failed");
        }
    }
    mcl::precomputeG2(lines, delta);
    for (size_t i = 0; i < count; ++i) {
        if (!write_field<FP6_BYTES>(output, lines[i])) {
            return fail("delta line serialization failed");
        }
    }
    const size_t TAIL_OFFSET = RAW_FIXED_KEY_BYTES + 3 * 64;
    if (!write_folded_ic(output, folded)
        || !output.append(raw + TAIL_OFFSET, RAW_PARAMETERS_BYTES - TAIL_OFFSET)
        || !output.finished()) {
        return fail("prepared IC serialization failed");
    }
    // No stdout bytes are emitted until every input and encoding has succeeded.
    if (fwrite(encoded, 1, output_size, stdout) != output_size || fflush(stdout) != 0) {
        return fail("output error");
    }
    return 0;
}
