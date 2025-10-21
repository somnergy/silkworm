#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <utility>
#include <vector>
#include <bit>
#include <evmone_precompiles/keccak.hpp>


#include <silkworm/core/common/bytes.hpp>
#include "mpt.hpp"

namespace silkworm::mpt {

// ---------------------------------------------
// HP (hex-prefix) compact encoding
// ---------------------------------------------

inline size_t hp_size(size_t nibbles) { return 1 + ((nibbles + 1) >> 1); }

inline uint8_t* encode_hp_path(uint8_t* out, const uint8_t* nib, size_t n, bool leaf) {
    const bool odd = (n & 1);
    const uint8_t flag = (leaf ? 0x2 : 0x0) | (odd ? 0x1 : 0x0);
    *out++ = static_cast<uint8_t>((flag << 4) | (odd ? (n ? (nib[0] & 0x0F) : 0) : 0));
    size_t i = odd ? 1 : 0;
    for (; i + 1 < n; i += 2) *out++ = static_cast<uint8_t>((nib[i] << 4) | (nib[i + 1] & 0x0F));
    if (i < n) *out++ = static_cast<uint8_t>((nib[i] << 4));  // last high nibble only
    return out;
}

// HP decode → (is_leaf, nibbles[]). Returns false on malformed.
inline bool hp_decode(ByteView in, bool& is_leaf, std::array<uint8_t, 64>& out, uint8_t& out_len) {
    if (in.empty()) return false;
    uint8_t flag = in[0] >> 4;
    is_leaf = (flag & 0x2) != 0;
    const bool odd = (flag & 0x1) != 0;
    uint8_t nib0 = in[0] & 0x0F;

    size_t pos = 1;
    out_len = 0;

    if (odd) {
        out[out_len++] = nib0 & 0x0F;
    }
    for (; pos < in.size(); ++pos) {
        out[out_len++] = (in[pos] >> 4) & 0x0F;
        out[out_len++] = in[pos] & 0x0F;
        if (out_len > 64) return false;
    }
    return true;
}

// --------------


inline evmc::bytes32 keccak_bytes(const Bytes& x) {
    return std::bit_cast<evmc_bytes32>(ethash_keccak256(reinterpret_cast<const uint8_t*>(x.data()), x.size()));
}

// Simple RLP reader utility - forward declaration
struct RlpReader;

}  // namespace silkworm::mpt
