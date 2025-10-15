#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::mpt {
using bytes32 = evmc::bytes32;

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

struct nibbles64 {
    uint8_t len{};                  // Upto what point it holds the path, could be a sub-path
    std::array<uint8_t, 64> nib{};  // each 0..15   // Maximum path a TrieNode can have is 64 nibbles

    // Convert a 32-byte key into 64 hex nibbles (0..15 per entry).
    static nibbles64 from_bytes32(const bytes32& k) {
        nibbles64 out;
        out.len = 64;
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
    uint16_t mask{};
    uint8_t count{};   // number of non-empty children
    ByteView value{};  // RLP "value" payload view (empty if none)
};

struct ExtensionNode {
    nibbles64 path;
    bytes32 child{};
};

struct LeafNode {
    nibbles64 path;
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
    bytes32 hash{};
    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };

    GridLine() : kind(kBranch), cur_slot(0), consumed(0), _pad(0) {
        std::memset(&branch, 0, sizeof(BranchNode));
    }
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

struct TrieNodeFlat {
    bytes32 key;
    ByteView value_rlp;
};

struct RlpReader {
    ByteView v;
    size_t i{0};
    ByteView v;
    size_t i{0};

    bool eof() const { return i >= v.size(); }
    uint8_t peek() const { return v[i]; }
    std::optional<ByteView> read_string();
    std::optional<ByteView> read_list_payload();
};

class GridMPT {
    std::array<GridLine, 64> grid_;
    uint8_t depth_{0};
    nibbles64 search_nibbles_;
    uint8_t search_nib_cursor_{0};
    nibbles64 previous_nibbles_;
    uint8_t fold_count_{0};

    // Flags
    bool should_unfold_{false};
    bool should_fold_{false};
    bool is_searching_{false};

    const NodeStore& node_store_;
    bytes32 prev_root;

    // Helper methods (easier to test individually)
    bool unfold_node_from_hash(const bytes32& hash, uint8_t parent_slot_index);
    bool fold_nibbles(int nib_count);
    bool fold_lines(uint8_t num_lines);
    bool insert_leaf(uint8_t slot, ByteView value_rlp);
    bool insert_extension(ExtensionNode& ext);
    bool insert_branch(BranchNode& bn, uint8_t slot);
    bool insert_branch(uint8_t slot);
    bytes32 calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted);
};

}  // namespace silkworm::mpt