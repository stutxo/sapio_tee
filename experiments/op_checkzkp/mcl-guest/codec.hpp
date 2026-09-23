#pragma once

#include <mcl/bn.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if MCL_FP_BIT != 256 || MCL_FR_BIT != 256
#error "G16L requires MCL_FP_BIT=256 and MCL_FR_BIT=256"
#endif

namespace checkzkp {

const size_t MAX_COEFFICIENTS = 128;
const size_t FP_BYTES = 32;
const size_t FP6_BYTES = 192;
const size_t FP12_BYTES = 384;
const size_t RAW_FIXED_KEY_BYTES = 64 + 3 * 128;
const size_t RAW_VK_BYTES = RAW_FIXED_KEY_BYTES + 7 * 64;
const size_t RAW_PARAMETERS_BYTES = RAW_VK_BYTES + 32;
const size_t PREPARED_BASE_BYTES = 4 + 4 + FP12_BYTES + 65 + 4 * 64 + 32;
const size_t MAX_PREPARED_BYTES = PREPARED_BASE_BYTES + 2 * MAX_COEFFICIENTS * FP6_BYTES;
const size_t PROOF_BYTES = 64 + 128 + 64;
const size_t WITNESS_BYTES = PROOF_BYTES + 32;

inline bool initialize_curve()
{
    bool ok;
    mcl::initPairing(&ok, mcl::BN_SNARK1);
    if (!ok) return false;
    // BN_SNARK1 G1 has cofactor one. G2::set below performs its one subgroup
    // check as well as the twist equation check; do not check it a second time.
    mcl::verifyOrderG1(false);
    mcl::verifyOrderG2(true);
    mcl::Fp::setETHserialization(false);
    mcl::Fr::setETHserialization(false);
    return mcl::Fp::getByteSize() == FP_BYTES && mcl::Fr::getByteSize() == FP_BYTES;
}

class Reader {
    const uint8_t* bytes_;
    size_t size_;
    size_t offset_;

public:
    Reader(const uint8_t* bytes, size_t size) : bytes_(bytes), size_(size), offset_(0) {}

    const uint8_t* take(size_t length)
    {
        if (length > size_ - offset_) return NULL;
        const uint8_t* result = bytes_ + offset_;
        offset_ += length;
        return result;
    }

    bool u32(uint32_t& value)
    {
        const uint8_t* p = take(4);
        if (!p) return false;
        value = uint32_t(p[0]) | (uint32_t(p[1]) << 8)
            | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
        return true;
    }

    bool finished() const { return offset_ == size_; }
};

class Writer {
    uint8_t* bytes_;
    size_t size_;
    size_t offset_;

public:
    Writer(uint8_t* bytes, size_t size) : bytes_(bytes), size_(size), offset_(0) {}

    uint8_t* take(size_t length)
    {
        if (length > size_ - offset_) return NULL;
        uint8_t* result = bytes_ + offset_;
        offset_ += length;
        return result;
    }

    bool append(const void* bytes, size_t length)
    {
        uint8_t* p = take(length);
        if (!p) return false;
        memcpy(p, bytes, length);
        return true;
    }

    bool u32(uint32_t value)
    {
        uint8_t* p = take(4);
        if (!p) return false;
        for (size_t i = 0; i < 4; ++i) p[i] = uint8_t(value >> (8 * i));
        return true;
    }

    bool finished() const { return offset_ == size_; }
};

inline size_t prepared_size(size_t count)
{
    return PREPARED_BASE_BYTES + 2 * count * FP6_BYTES;
}

inline bool read_fp(Reader& reader, mcl::Fp& value)
{
    const uint8_t* p = reader.take(FP_BYTES);
    if (!p) return false;
    uint8_t little[FP_BYTES];
    for (size_t i = 0; i < FP_BYTES; ++i) little[i] = p[FP_BYTES - 1 - i];
    // Public deserialize rejects integers >= p; no reduction, masking, or
    // copying of native Montgomery limbs is part of the wire protocol.
    return value.deserialize(little, sizeof(little)) == sizeof(little);
}

inline bool read_scalar_half(const uint8_t* half, mcl::Fr& value)
{
    uint8_t little[FP_BYTES] = {};
    for (size_t i = 0; i < 16; ++i) little[i] = half[15 - i];
    return value.deserialize(little, sizeof(little)) == sizeof(little);
}

inline bool read_g1(Reader& reader, mcl::G1& point)
{
    mcl::Fp x, y;
    if (!read_fp(reader, x) || !read_fp(reader, y)) return false;
    bool ok;
    point.set(&ok, x, y);
    return ok && !point.isZero();
}

inline bool read_g2(Reader& reader, mcl::G2& point)
{
    mcl::Fp2 x, y;
    // Ordinary big-endian x.c0 || x.c1 || y.c0 || y.c1.
    if (!read_fp(reader, x.a) || !read_fp(reader, x.b)
        || !read_fp(reader, y.a) || !read_fp(reader, y.b)) return false;
    bool ok;
    point.set(&ok, x, y);
    return ok && !point.isZero();
}

inline bool read_folded_ic(Reader& reader, mcl::G1& point)
{
    const uint8_t* tag = reader.take(1);
    if (!tag) return false;
    if (*tag == 1) return read_g1(reader, point);
    if (*tag != 0) return false;
    const uint8_t* encoded = reader.take(64);
    if (!encoded) return false;
    for (size_t i = 0; i < 64; ++i) {
        if (encoded[i] != 0) return false;
    }
    point.clear();
    return true;
}

inline bool write_fp(Writer& writer, const mcl::Fp& value)
{
    uint8_t little[FP_BYTES];
    if (value.serialize(little, sizeof(little)) != sizeof(little)) return false;
    uint8_t* p = writer.take(FP_BYTES);
    if (!p) return false;
    for (size_t i = 0; i < FP_BYTES; ++i) p[i] = little[FP_BYTES - 1 - i];
    return true;
}

inline bool write_folded_ic(Writer& writer, const mcl::G1& point)
{
    uint8_t* tag = writer.take(1);
    if (!tag) return false;
    if (point.isZero()) {
        *tag = 0;
        uint8_t* p = writer.take(64);
        if (!p) return false;
        memset(p, 0, 64);
        return true;
    }
    *tag = 1;
    mcl::G1 affine;
    mcl::G1::normalize(affine, point);
    return write_fp(writer, affine.x) && write_fp(writer, affine.y);
}

template<size_t Bytes, class Field>
inline bool read_field(Reader& reader, Field& value)
{
    const uint8_t* p = reader.take(Bytes);
    // Fp6/Fp12's public codecs load each canonical Fp, in MCL's ordinary
    // little-endian serialization order, independent of limb size/platform.
    return p && value.deserialize(p, Bytes) == Bytes;
}

template<size_t Bytes, class Field>
inline bool write_field(Writer& writer, const Field& value)
{
    uint8_t* p = writer.take(Bytes);
    return p && value.serialize(p, Bytes) == Bytes;
}

} // namespace checkzkp
