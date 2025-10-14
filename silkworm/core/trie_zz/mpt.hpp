
// #pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
using namespace evmc;

namespace silkworm::mpt {

#if defined(__cpp_threadsafe_static_init) && !defined(NO_THREAD_LOCAL) && !defined(SP1)
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

struct Nibbles64 {
    unsigned int len{};
    std::array<uint8_t, 64> nib{};  // each 0..15
    // Convert a 32-byte key into 64 hex nibbles (0..15 per entry).
    static Nibbles64 from_bytes32(const bytes32& k) {
        Nibbles64 out;
        for (size_t i = 0; i < 32; ++i) {
            uint8_t b = k.bytes[i];
            out.nib[2 * i] = (b >> 4) & 0x0F;
            out.nib[2 * i + 1] = b & 0x0F;
        }
        return out;
    }
};

struct BranchNode {
    alignas(32) std::array<bytes32, 16> child{};
    uint8_t mask{};    // bit i set if child[i] non-zero
    uint8_t count{};   // number of non-empty children
    ByteView value{};  // RLP "value" payload view (empty if none)
};

struct ExtensionNode {
    Nibbles64 path;
    bytes32 child{};
};

struct LeafNode {
    Nibbles64 path;
    ByteView value{};
};

inline bool is_zero_quick(const bytes32& h) {
    auto words = std::bit_cast<std::array<std::uint32_t, 8>>(h);
    return (words[0] | words[1] | words[2] | words[3] |
            words[4] | words[5] | words[6] | words[7]) == 0;
}
inline void zero(bytes32& h) { std::memset(h.bytes, 0, 32); }

enum Kind : uint8_t {
    kBranch = 0,
    kExt = 1,
    kLeaf = 2
};

struct GridLine {
    uint8_t kind;      // Kind
    uint8_t cur_slot;  // parent child index (0..15) or 16 = branch value
    uint8_t consumed;  // nibbles consumed at this node (ext/leaf)
    uint8_t _pad;
    bytes32 hash{};  // Probably not needed
    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };
};

// ---------------------------------------------
// Store interface: get RLP by hash; sink new nodes
// ---------------------------------------------

struct NodeStore {
    // Must return the RLP bytes for `hash` (throws/asserts if missing).
    std::function<ByteView(const bytes32&)> get_rlp;

    // Optional: sink newly created nodes (hash -> RLP) after fold.
    std::function<void(const bytes32&, const Bytes&)> put_rlp;
};

}  // namespace silkworm::mpt