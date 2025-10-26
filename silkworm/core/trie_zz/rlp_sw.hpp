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
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>

#include "helpers.hpp"
#include "mpt.hpp"

namespace silkworm::mpt {
#if defined(__cpp_threadsafe_static_init) && !defined(NO_THREAD_LOCAL) && !defined(SP1) && !defined(QEMU_DEBUG)
inline thread_local Bytes static_buffer = []() {
    Bytes buf;
    buf.reserve(1024);
    return buf;
}();
#else
inline static Bytes static_buffer = []() {
    Bytes buf;
    buf.reserve(1024);
    return buf;
}();
#endif

// Helper to clear static buffer between test runs
inline void clear_static_buffer() {
    static_buffer.clear();
    static_buffer.reserve(1024);
}

// ---------------------------------------------
// RLP encoding using Silkworm's rlp namespace
// ---------------------------------------------

// See "Specification: Compact encoding of hex sequence with optional terminator"
// at https://eth.wiki/fundamentals/patricia-tree
inline Bytes encode_path(ByteView nibbles, bool terminating) {
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

inline Bytes encode_branch(const BranchNode& b) {
    static_buffer.clear();
    rlp::Header h{.list = true, .payload_length = 0};
    // Calculate payload for 16 children
    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];

        // No double encoding
        h.payload_length += (child_len == 0 || child_len == 32)
                                ? 1 + child_len
                                : child_len;
        
        // Double encoding of embedded node
        // h.payload_length += 1 + child_len;
    }

    h.payload_length += rlp::length(b.value);
    rlp::encode_header(static_buffer, h);

    // Encode 16 children
    //  std::cout<< "\n BR: Child At: ";
    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];
        if (child_len == 0) {
            static_buffer.push_back(rlp::kEmptyStringCode);
        } else if (child_len == 32) {
            // hashed ref
            static_buffer.push_back({0xa0});
            static_buffer.append(b.child[i].bytes, b.child_len[i]);
        }
        else {
            // No double encoding
            static_buffer.append(b.child[i].bytes, b.child_len[i]);

            // Double encoding of embedded node
            // rlp::encode(static_buffer, ByteView{b.child[i].bytes, b.child_len[i]});
        }
    }
    // std::cout<< "\n";

    rlp::encode(static_buffer, b.value);
    std::cout << "call to encode_branch " << static_buffer << std::endl;
    return static_buffer;
}

inline Bytes encode_ext(const ExtensionNode& e) {
    static_buffer.clear();
    ByteView path{e.path.nib.data(), e.path.len};
    std::cout << "encode_ext path:  " << path << std::endl;

    Bytes hp_encoded{encode_path(path, /*terminating=*/false)};

    // Calculate payload length
    size_t child_rlp_len;
    if (e.child_len == 32) {
        // Hash reference: needs RLP encoding (0xa0 + 32 bytes = 33 bytes)
        child_rlp_len = 33;
    } else {
        // Embedded node or already RLP-encoded
        child_rlp_len = e.child_len;
    }

    rlp::Header h{
        .list = true,
        .payload_length = rlp::length(hp_encoded) + child_rlp_len};
    rlp::encode_header(static_buffer, h);
    rlp::encode(static_buffer, hp_encoded);

    // Encode child
    if (e.child_len == 32) {
        // Hash reference: RLP-encode the 32-byte hash
        ByteView child_hash{e.child.bytes, 32};
        rlp::encode(static_buffer, child_hash);
    } else {
        // Embedded node: already RLP-encoded, append as-is
        static_buffer.append(e.child.bytes, e.child_len);
    }

    std::cout << "call to encode_ext " << static_buffer << std::endl;

    return static_buffer;
}

inline Bytes encode_leaf(const LeafNode& l) {
    static_buffer.clear();

    // Bytes path{l.path.nib.data(), l.path.len};
    // std::cout << "encode_leaf path:  " << l.path.nib << std::endl;

    // Encode HP path
    uint8_t hpbuf[1 + 32];
    uint8_t* hp_end = encode_hp_path(hpbuf, l.path.nib.data(), l.path.len, /*leaf*/ true);
    ByteView hp_encoded{hpbuf, static_cast<size_t>(hp_end - hpbuf)};

    rlp::Header h{.list = true, .payload_length = 0};
    h.payload_length += rlp::length(hp_encoded);
    h.payload_length += rlp::length(l.value);

    rlp::encode_header(static_buffer, h);
    rlp::encode(static_buffer, hp_encoded);
    rlp::encode(static_buffer, l.value);
    return static_buffer;
}

// ---------------------------------------------
// RLP decoding using Silkworm's rlp namespace
// RLP Reader implementation (full version with decode_header support)
struct RlpReader {
    ByteView v;
    size_t original_size{0};

    explicit RlpReader(ByteView view) : v(view), original_size(view.size()) {}

    bool eof() const { return v.empty(); }
    uint8_t peek() const { return v.empty() ? 0 : v[0]; }

    std::optional<ByteView> read_string() {
        auto header = rlp::decode_header(v);
        if (!header) return std::nullopt;
        if (header->list) return std::nullopt;

        ByteView result = v.substr(0, header->payload_length);
        v.remove_prefix(header->payload_length);
        return result;
    }

    std::optional<ByteView> read_list_payload() {
        auto header = rlp::decode_header(v);
        if (!header) return std::nullopt;
        if (!header->list) return std::nullopt;

        ByteView result = v.substr(0, header->payload_length);
        v.remove_prefix(header->payload_length);
        return result;
    }
};

// ---------------------------------------------
// Decoding helpers for MPT nodes
// ---------------------------------------------

inline bool decode_branch(ByteView payload, BranchNode& out) {
    // FIX: Initialize mask and count
    out.mask = 0;
    out.count = 0;

    ByteView remaining = payload;

    // Decode 16 children
    for (size_t i = 0; i < 16; ++i) {
        // Save position before decode_header consumes the header
        // const uint8_t* child_start = remaining.data();

        auto hdr = rlp::decode_header(remaining);
        if (!hdr || hdr->list) return false;

        if (hdr->payload_length == 0) {
            // Empty child (RLP empty string 0x80)
            zero(out.child[i]);
            out.child_len[i] = 0;
        } else {
            // Non-empty child: store the full RLP-encoded form (header + payload)
            // size_t header_len = static_cast<size_t>(remaining.data() - child_start);
            // size_t total_len = header_len + hdr->payload_length;
            // std::memcpy(out.child[i].bytes, child_start, total_len);
            // out.child_len[i] = static_cast<uint8_t>(total_len);
            out.child_len[i] = hdr->payload_length;
            std::memcpy(out.child[i].bytes, remaining.data(), hdr->payload_length);
            out.mask |= (1 << i);
            out.count++;
        }
        remaining.remove_prefix(hdr->payload_length);
    }

    // Decode value (17th element)
    auto hdr_value = rlp::decode_header(remaining);
    if (!hdr_value || hdr_value->list) return false;
    out.value = remaining.substr(0, hdr_value->payload_length);
    remaining.remove_prefix(hdr_value->payload_length);

    // Should have consumed everything
    return remaining.empty();
}

inline bool decode_ext_or_leaf(ByteView payload, bool& is_leaf,
                               std::array<uint8_t, 64>& path, uint8_t& plen,
                               ByteView& second) {
    ByteView remaining = payload;

    // First element - HP encoded path
    auto h1 = rlp::decode_header(remaining);
    if (!h1 || h1->list) return false;
    ByteView hp_path = remaining.substr(0, h1->payload_length);
    remaining.remove_prefix(h1->payload_length);

    // Decode HP path first to determine if it's a leaf or extension
    if (!hp_decode(hp_path, is_leaf, path, plen)) {
        return false;
    }

    // Second element - child hash (for extension) or value (for leaf)
    const uint8_t* second_start = remaining.data();
    auto h2 = rlp::decode_header(remaining);
    if (!h2 || h2->list) return false;

    if (!is_leaf) {
        // Extension: for hash references, return just the 32-byte hash (not RLP-encoded)
        // For embedded nodes, return the full RLP
        if (h2->payload_length == 32) {
            // Hash reference: return just the payload (32 bytes)
            second = remaining.substr(0, 32);
        } else {
            // Embedded node: return full RLP-encoded form (header + payload)
            size_t header_len = static_cast<size_t>(remaining.data() - second_start);
            size_t total_len = header_len + h2->payload_length;
            second = ByteView{second_start, total_len};
        }
    } else {
        // Leaf: return just the value payload
        second = remaining.substr(0, h2->payload_length);
    }

    remaining.remove_prefix(h2->payload_length);

    // Should have consumed everything
    return remaining.empty();
}

}  // namespace silkworm::mpt