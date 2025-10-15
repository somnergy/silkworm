#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <evmone_precompiles/keccak.hpp>

#include <silkworm/core/common/bytes.hpp>

#include "mpt.hpp"
#include "helpers.hpp"

namespace silkworm::mpt {
// ---------------------------------------------
// RLP minimal helpers (strings + list headers)
// ---------------------------------------------

inline size_t rlp_size_str(size_t n, bool single_byte_is_literal, uint8_t first_byte = 0) {
    if (single_byte_is_literal && n == 1 && first_byte < 0x80) return 1;
    if (n <= 55) return 1 + n;
    int L = 0;
    for (size_t t = n; t; t >>= 8) ++L;
    return 1 + L + n;
}
inline uint8_t* rlp_put_str(uint8_t* out, const uint8_t* s, size_t n,
                            bool single_byte_is_literal, uint8_t first_byte = 0) {
    if (single_byte_is_literal && n == 1 && first_byte < 0x80) {
        *out++ = first_byte;
        return out;
    }
    if (n <= 55) {
        *out++ = static_cast<uint8_t>(0x80 + n);
        if (n) {
            std::memcpy(out, s, n);
            out += n;
        }
        return out;
    }
    int L = 0;
    size_t t = n;
    uint8_t tmp[9];
    do {
        tmp[8 - (++L)] = static_cast<uint8_t>(t);
        t >>= 8;
    } while (t);
    *out++ = static_cast<uint8_t>(0xB7 + L);
    std::memcpy(out, tmp + 9 - L, L);
    out += L;
    std::memcpy(out, s, n);
    out += n;
    return out;
}
inline size_t rlp_size_list(size_t payload) {
    if (payload <= 55) return 1 + payload;
    int L = 0;
    for (size_t t = payload; t; t >>= 8) ++L;
    return 1 + L + payload;
}
inline uint8_t* rlp_put_list_hdr(uint8_t* out, size_t payload) {
    if (payload <= 55) {
        *out++ = static_cast<uint8_t>(0xC0 + payload);
        return out;
    }
    int L = 0;
    size_t t = payload;
    uint8_t tmp[9];
    do {
        tmp[8 - (++L)] = static_cast<uint8_t>(t);
        t >>= 8;
    } while (t);
    *out++ = static_cast<uint8_t>(0xF7 + L);
    std::memcpy(out, tmp + 9 - L, L);
    out += L;
    return out;
}

inline Bytes encode_branch(const BranchNode& b) {
    // Size inner items
    size_t inner = 0;
    for (int i = 0; i < 16; ++i) inner += rlp_size_str(evmc::is_zero(b.child[i]) ? 0 : 32, /*literal*/ false);
    inner += rlp_size_str(b.value.size(), /*literal*/ true, b.value.size() ? b.value[0] : 0x00);
    // Out buf
    Bytes out;
    out.resize(rlp_size_list(inner));
    uint8_t* p = reinterpret_cast<uint8_t*>(out.data());
    p = rlp_put_list_hdr(p, inner);
    // 16 children
    for (int i = 0; i < 16; ++i) {
        if (is_zero(b.child[i])) {
            *p++ = 0x80;
        } else
            p = rlp_put_str(p, b.child[i].bytes, 32, /*literal*/ false);
    }
    // value
    if (b.value.size() == 0) {
        *p++ = 0x80;
    } else
        p = rlp_put_str(p, b.value.data(), b.value.size(), /*literal*/ true, b.value[0]);
    return out;
}

inline Bytes encode_ext(const ExtensionNode& e) {
    const size_t hp_sz = hp_size(e.path.len);
    const size_t s0 = rlp_size_str(hp_sz, false);
    const size_t s1 = rlp_size_str(32, false);
    const size_t inner = s0 + s1;
    Bytes out;
    out.resize(rlp_size_list(inner));
    uint8_t* p = reinterpret_cast<uint8_t*>(out.data());
    p = rlp_put_list_hdr(p, inner);
    // item0
    {
        // Write the HP-encoded path to a tiny temp
        uint8_t hpbuf[1 + 32];  // 65 max
        uint8_t* q = encode_hp_path(hpbuf, e.path.nib.data(), e.path.len, /*leaf*/ false);
        p = rlp_put_str(p, hpbuf, size_t(q - hpbuf), false);
    }
    // item1
    p = rlp_put_str(p, e.child.bytes, 32, false);
    return out;
}

inline Bytes encode_leaf(const LeafNode& l) {
    const size_t hp_sz = hp_size(l.path.len);
    const size_t s0 = rlp_size_str(hp_sz, false);
    const size_t s1 = rlp_size_str(l.value.size(), true, l.value.size() ? l.value[0] : 0);
    const size_t inner = s0 + s1;
    Bytes out;
    out.resize(rlp_size_list(inner));
    uint8_t* p = reinterpret_cast<uint8_t*>(out.data());
    p = rlp_put_list_hdr(p, inner);
    // item0
    {
        uint8_t hpbuf[1 + 32];
        uint8_t* q = encode_hp_path(hpbuf, l.path.nib.data(), l.path.len, /*leaf*/ true);
        p = rlp_put_str(p, hpbuf, size_t(q - hpbuf), false);
    }
    // item1
    if (l.value.size() == 0)
        *p++ = 0x80;
    else
        p = rlp_put_str(p, l.value.data(), l.value.size(), true, l.value[0]);
    return out;
}


// Minimal RLP reader just for this use case.
// Read an RLP string (returns view), or empty if malformed.
std::optional<ByteView> RlpReader::read_string() {
    if (eof()) return std::nullopt;
    uint8_t b = v[i++];
    if (b <= 0x7f) {  // single byte literal
        return ByteView{&v[i - 1], 1};
    } else if (b <= 0xb7) {
        size_t len = b - 0x80;
        if (i + len > v.size()) return std::nullopt;
        ByteView out{&v[i], len};
        i += len;
        return out;
    } else if (b <= 0xbf) {
        size_t lenlen = b - 0xb7;
        if (i + lenlen > v.size()) return std::nullopt;
        size_t len = 0;
        for (size_t k = 0; k < lenlen; ++k) len = (len << 8) | v[i + k];
        i += lenlen;
        if (i + len > v.size()) return std::nullopt;
        ByteView out{&v[i], len};
        i += len;
        return out;
    }
    return std::nullopt;  // lists start at C0
}
// Read a list payload view (no element parsing here).
std::optional<ByteView> RlpReader::read_list_payload() {
    if (eof()) return std::nullopt;
    uint8_t b = v[i++];
    if (b <= 0xf7) {
        if (b < 0xc0) return std::nullopt;
        size_t len = b - 0xc0;
        if (i + len > v.size()) return std::nullopt;
        ByteView out{&v[i], len};
        i += len;
        return out;
    } else {
        size_t lenlen = b - 0xf7;
        if (i + lenlen > v.size()) return std::nullopt;
        size_t len = 0;
        for (size_t k = 0; k < lenlen; ++k) len = (len << 8) | v[i + k];
        i += lenlen;
        if (i + len > v.size()) return std::nullopt;
        ByteView out{&v[i], len};
        i += len;
        return out;
    }
}


}  // namespace silkworm::trie