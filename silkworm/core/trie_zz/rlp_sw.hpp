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
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/rlp/decode.hpp>

#include "mpt.hpp"
#include "helpers.hpp"

namespace silkworm::mpt {

// ---------------------------------------------
// RLP encoding using Silkworm's rlp namespace
// ---------------------------------------------

inline Bytes encode_branch(const BranchNode& b) {
    // Use the static_buffer from mpt.hpp (it already has thread_local handling)
    static_buffer.clear();
    
    rlp::Header h{.list = true, .payload_length = 0};
    
    // Calculate payload for 16 children
    for (size_t i = 0; i < 16; ++i) {
        h.payload_length += is_zero(b.child[i]) 
            ? size_t{1}  // RLP("") == 0x80
            : rlp::length(ByteView{b.child[i].bytes, 32});
    }
    
    // Add value field
    h.payload_length += rlp::length(b.value);
    
    // FIX: Reserve correctly with +1 for list header byte
    const size_t total_size = 1 + rlp::length_of_length(h.payload_length) + h.payload_length;
    static_buffer.reserve(total_size);
    
    rlp::encode_header(static_buffer, h);
    
    // Encode 16 children
    for (size_t i = 0; i < 16; ++i) {
        if (is_zero(b.child[i])) {
            static_buffer.push_back(rlp::kEmptyStringCode);
        } else {
            rlp::encode(static_buffer, ByteView{b.child[i].bytes, 32});
        }
    }
    
    rlp::encode(static_buffer, b.value);
    return static_buffer;
}

inline Bytes encode_ext(const ExtensionNode& e) {
    static_buffer.clear();
    
    // Encode HP path
    uint8_t hpbuf[1 + 32];  // Max 33 bytes for 64 nibbles
    uint8_t* hp_end = encode_hp_path(hpbuf, e.path.nib.data(), e.path.len, /*leaf*/ false);
    ByteView hp_encoded{hpbuf, static_cast<size_t>(hp_end - hpbuf)};
    
    rlp::Header h{.list = true, .payload_length = 0};
    h.payload_length += rlp::length(hp_encoded);
    h.payload_length += rlp::length(ByteView{e.child.bytes, 32});
    
    // FIX: Reserve correctly with +1 for list header byte
    const size_t total_size = 1 + rlp::length_of_length(h.payload_length) + h.payload_length;
    static_buffer.reserve(total_size);
    
    rlp::encode_header(static_buffer, h);
    rlp::encode(static_buffer, hp_encoded);
    rlp::encode(static_buffer, ByteView{e.child.bytes, 32});
    
    return static_buffer;
}

inline Bytes encode_leaf(const LeafNode& l) {
    static_buffer.clear();
    
    // Encode HP path
    uint8_t hpbuf[1 + 32];
    uint8_t* hp_end = encode_hp_path(hpbuf, l.path.nib.data(), l.path.len, /*leaf*/ true);
    ByteView hp_encoded{hpbuf, static_cast<size_t>(hp_end - hpbuf)};
    
    rlp::Header h{.list = true, .payload_length = 0};
    h.payload_length += rlp::length(hp_encoded);
    h.payload_length += rlp::length(l.value);
    
    // FIX: Reserve correctly with +1 for list header byte
    const size_t total_size = 1 + rlp::length_of_length(h.payload_length) + h.payload_length;
    static_buffer.reserve(total_size);
    
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
        auto hdr = rlp::decode_header(remaining);
        if (!hdr || hdr->list) return false;
        
        ByteView elem_payload = remaining.substr(0, hdr->payload_length);
        remaining.remove_prefix(hdr->payload_length);
        
        if (elem_payload.empty()) {
            zero(out.child[i]);
        } else if (elem_payload.size() == 32) {
            std::memcpy(out.child[i].bytes, elem_payload.data(), 32);
            // FIX: Update mask and count
            out.mask |= static_cast<uint16_t>(1u << i);
            ++out.count;
        } else {
            // Strictly enforce hash-only children (no inlining)
            return false;
        }
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
    
    // Second element - child hash (for extension) or value (for leaf)
    auto h2 = rlp::decode_header(remaining);
    if (!h2 || h2->list) return false;
    second = remaining.substr(0, h2->payload_length);
    remaining.remove_prefix(h2->payload_length);
    
    // Should have consumed everything
    if (!remaining.empty()) return false;
    
    // Decode HP path
    if (!hp_decode(hp_path, is_leaf, path, plen )) {
        return false;
    }
    
    // FIX: Validate extension child is exactly 32 bytes (hash-only)
    if (!is_leaf && second.size() != 32) {
        return false;
    }
    
    return true;
}

}  // namespace silkworm::mpt