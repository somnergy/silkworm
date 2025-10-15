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

static Bytes encode_path(ByteView nibbles, bool terminating) {
    Bytes res(nibbles.size() / 2 + 1, '\0');
    const bool odd{static_cast<bool>((nibbles.size() & 1u) != 0)};

    res[0] = terminating ? 0x20 : 0x00;
    res[0] += odd ? 0x10 : 0x00;

    if (odd) {
        res[0] |= nibbles[0];
        nibbles.remove_prefix(1);
    }

    for (auto it{std::next(res.begin(), 1)}, end{res.end()}; it != end; ++it) {
        *it = static_cast<uint8_t>((nibbles[0] << 4) + nibbles[1]);
        nibbles.remove_prefix(2);
    }

    return res;
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

inline bool decode_branch(ByteView payload, BranchNode& br) {
    // Expect exactly 17 RLP strings concatenated inside payload.
    RlpReader it{payload};
    for (int idx = 0; idx < 16; ++idx) {
        auto s = it.read_string();
        if (!s) return false;
        if (s->size() == 0) {
            zero(br.child[idx]);
        } else {
            if (s->size() != 32) return false;
            std::memcpy(br.child[idx].bytes, s->data(), 32);
            br.mask |= static_cast<uint16_t>(1u << idx);
            ++br.count;
        }
    }
    auto val = it.read_string();
    if (!val) return false;
    br.value = {val->data(), val->size()};
    return it.eof();
}

inline bool decode_ext_or_leaf(ByteView payload, bool& is_leaf,
                               std::array<uint8_t, 64>& path_out, uint8_t& path_len_out,
                               ByteView& second) {
    RlpReader it{payload};
    auto p0 = it.read_string();
    if (!p0) return false;
    if (!hp_decode(*p0, is_leaf, path_out, path_len_out)) return false;
    auto p1 = it.read_string();
    if (!p1) return false;
    second = *p1;
    return it.eof();
}



// Hex-Prefix encode-decode functions
inline size_t hp_size(size_t nibbles) { return 1 + ((nibbles + 1) >> 1); }

inline uint8_t* encode_hp_path(uint8_t* p, const uint8_t* nib, size_t n, bool leaf) {
    const bool odd = (n & 1);
    const uint8_t flag = (leaf ? 0x2 : 0x0) | (odd ? 0x1 : 0x0);
    *p++ = static_cast<uint8_t>((flag << 4) | (odd ? (n ? (nib[0] & 0x0F) : 0) : 0));
    size_t i = odd ? 1 : 0;
    for (; i + 1 < n; i += 2) *p++ = static_cast<uint8_t>((nib[i] << 4) | (nib[i + 1] & 0x0F));
    if (i < n) *p++ = static_cast<uint8_t>((nib[i] << 4));  // last high nibble only
    return p;
}

// HP decode -> (is_leaf, nibbles[]). Returns false on malformed.
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

// Create a leaf for remaining key suffix (after consuming one child nibble already if needed)
inline bytes32 make_leaf_for_suffix(const uint8_t* suffix, uint8_t len, ByteView value,
                                    const NodeStore& store) {
    LeafNode l{};
    l.path.len = len;
    if (len) std::memcpy(l.path.nib.data(), suffix, len);
    l.value = value;
    Bytes enc = encode_leaf(l);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

// Make a branch with two children per a split: old (from existing child), new (from key suffix)
inline bytes32 make_branch_two_children(uint8_t old_idx, const bytes32& old_child_hash,
                                        uint8_t new_idx, const uint8_t* new_suffix, uint8_t new_len,
                                        ByteView new_value, const NodeStore& store) {
    BranchNode b{};
    // Old side: place existing subtree under old_idx
    b.child[old_idx] = old_child_hash;
    b.mask |= static_cast<uint16_t>(1u << old_idx);
    b.count++;
    // New side: create a new leaf for new suffix (after consuming new_idx)
    bytes32 new_leaf = make_leaf_for_suffix(new_suffix, new_len, new_value, store);
    b.child[new_idx] = new_leaf;
    b.mask |= static_cast<uint16_t>(1u << new_idx);
    b.count++;
    // Encode & hash
    Bytes enc = encode_branch(b);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

// Wrap a child under a single-nibble Extension prefix (path one nibble)
inline bytes32 wrap_ext_1(uint8_t nib, const bytes32& child, const NodeStore& store) {
    ExtensionNode e{};
    e.path.len = 1;
    e.path.nib[0] = nib;
    e.child = child;
    Bytes enc = encode_ext(e);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

// Build an Extension over a Branch for a common prefix of length m>=1
inline bytes32 wrap_ext_multi(const uint8_t* common, uint8_t m, const bytes32& child,
                              const NodeStore& store) {
    ExtensionNode e{};
    e.path.len = m;
    std::memcpy(e.path.nib.data(), common, m);
    e.child = child;
    Bytes enc = encode_ext(e);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}
}  // namespace silkworm::mpt
