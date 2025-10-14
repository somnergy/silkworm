// #pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>


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

// Minimal RLP reader just for this use case.
struct RlpReader {
    ByteView v;
    size_t i{0};

    bool eof() const { return i >= v.size(); }
    uint8_t peek() const { return v[i]; }

    // Read an RLP string (returns view), or empty if malformed.
    std::optional<ByteView> read_string() {
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
    std::optional<ByteView> read_list_payload() {
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
};

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

// Decode node from hash into a GridLine and push onto stack.
inline bool unfold_node_from_hash(const NodeStore& store, const bytes32& hash,
                                  GridLine& grid_line, uint8_t parent_slot_index) {
    ByteView rlp = store.get_rlp(hash);
    grid_line.hash = hash;
    grid_line.cur_slot = parent_slot_index;
    // Peek first byte to detect list; then sub-parse.
    RlpReader rr{rlp};
    auto list = rr.read_list_payload();
    if (!list) return false;

    // Try branch first: 17 concatenated items
    // To distinguish: we need to attempt decoding as (17 strings). If it fails, try (2 items).
    // A quick heuristic: count inner elements by walking; but we have a minimal reader—decode each shape directly.

    // Try as branch:
    {
        BranchNode tmp{};
        if (decode_branch(*list, tmp)) {
            grid_line.kind = kBranch;
            std::memcpy(&grid_line.branch, &tmp, sizeof(tmp));  // POD copy
            return true;
        }
    }
    // Else extension/leaf:
    bool is_leaf = false;
    std::array<uint8_t, 64> path{};
    uint8_t plen = 0;
    ByteView second{};
    if (!decode_ext_or_leaf(*list, is_leaf, path, plen, second)) return false;
    if (is_leaf) {
        grid_line.kind = kLeaf;
        grid_line.leaf.path.len = plen;
        std::memcpy(grid_line.leaf.path.nib.data(), path.data(), plen);
        grid_line.leaf.value = {second.data(), second.size()};
    } else {
        if (second.size() != 32) return false;  // we store child as hash
        grid_line.kind = kExt;
        grid_line.ext.path.len = plen;
        std::memcpy(grid_line.ext.path.nib.data(), path.data(), plen);
        std::memcpy(grid_line.ext.child.bytes, second.data(), 32);
    }
    return true;
}
}  // namespace silkworm::mpt
