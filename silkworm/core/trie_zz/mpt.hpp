#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include "node_store_i.hpp"
namespace silkworm::mpt {
using bytes32 = evmc::bytes32;

struct nibbles64 {
    uint8_t len{};                  // Upto what point it holds the path, could be a sub-path
    std::array<uint8_t, 64> nib{};  // each 0..15   // Maximum path a TrieNode can have is 64 nibbles

    // Operator overloads for direct array access
    uint8_t& operator[](size_t index) { return nib[index]; }
    const uint8_t& operator[](size_t index) const { return nib[index]; }

    // Convert a 32-byte key into 64 hex nibbles (0..15 per entry).
    static nibbles64 from_bytes32(const bytes32& k) {
        nibbles64 out;
        out.len = 64;
        for (size_t i = 0; i < 32; ++i) {
            uint8_t b = k.bytes[i];
            out[2 * i] = (b >> 4) & 0x0F;
            out[2 * i + 1] = b & 0x0F;
        }
        return out;
    }
};

struct BranchNode {
    alignas(32) std::array<bytes32, 16> child{};
    std::array<uint8_t, 16> child_len{};
    uint16_t mask{};
    uint8_t count{};   // number of non-empty children
    ByteView value{};  // RLP "value" payload view (empty if none)

    // Explicit constructor to ensure zero-initialization
    BranchNode() {
        child = {};
        child_len = {};
        mask = 0;
        count = 0;
        value = ByteView{};
    }

    inline void set_child(uint8_t slot, Bytes& b) {
        std::memcpy(child[slot].bytes, b.data(), b.size());
        child_len[slot] = static_cast<uint8_t>(b.size());
    }
};

struct ExtensionNode {
    nibbles64 path;
    bytes32 child{};
    uint8_t child_len;

    inline void set_child(Bytes& b) {
        std::memcpy(child.bytes, b.data(), b.size());
        child_len = static_cast<uint8_t>(b.size());
    }
};

struct LeafNode {
    nibbles64 path;
    uint8_t parent_slot;
    ByteView value{};
};

inline bool is_zero_quick(const bytes32& h) {
    auto words = std::bit_cast<std::array<std::uint32_t, 8>>(h);
    return (words[0] | words[1] | words[2] | words[3] |
            words[4] | words[5] | words[6] | words[7]) == 0;
}
inline bool is_zero_quick(const Bytes& b) {
    return std::all_of(b.begin(), b.end(), [](uint8_t byte) { return byte == 0; });
}
inline void zero(bytes32& h) { std::memset(h.bytes, 0, 32); }

enum Kind : uint8_t {
    kBranch = 0,
    kExt = 1,
    kLeaf = 2
};

struct GridLine {
    uint8_t kind;          // Kind
    uint8_t parent_slot;   // parent child index (0..15) or 16 = branch value
    uint8_t parent_depth;  // Depth in the stack the current line's parent is at
    uint8_t consumed;      // path nibbles consumed till this node (cumulative)
    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };

    GridLine() : kind(kBranch), parent_slot(0), parent_depth(0), consumed(0), branch{} {}
    GridLine(uint8_t k, uint8_t pslot, uint8_t pdepth, uint8_t c) : kind{k}, parent_slot{pslot}, parent_depth{pdepth}, consumed{c} {}
};



struct TrieNodeFlat {
    bytes32 key;
    Bytes value_rlp;
};

// A class holding the data for the Trie root calculation
// Proceeds as follows:
// Search a key by going down the tree (unfolding)
// When you find a position to insert, insert there and
// recalulcate the hash of that node all the way up (folding)
// If there are more keys to insert, find a common divergence point
// and insert the new key there before folding further.
// More unfolding and folding needed for this or more keys
class GridMPT {
    uint8_t depth_{0};              // The current depth we are visiting
    uint8_t search_nib_cursor_{0};  // The position in the current search key
    uint8_t cur_unfold_depth_{0};
    std::array<uint8_t, 16> unfolded_child_{};  // Depths of children of current branch, if unfolded
    // Previous root of the trie
    bytes32 prev_root_;
    // A stack of grid-lines consisting of TrieNodes
    std::vector<GridLine> grid_;
    nibbles64 search_nibbles_;    // The current key being searched for/inserted
    nibbles64 previous_nibbles_;  // The last searched key

    // Flags
    bool should_unfold_{false};
    bool should_fold_{false};
    bool is_searching_{false};

    // A store containing the set of keys to be inserted
    NodeStore& node_store_;

    // Helper methods
    bool unfold_node_from_rlp(ByteView rlp, uint8_t parent_slot_index, uint8_t parent_depth);
    bool fold_nibbles(int nib_count);
    uint8_t fold_back();
    bool fold_lines(uint8_t num_lines);
    // bytes32 make_leaf_for_suffix(const uint8_t* suffix, uint8_t len, ByteView value);
    LeafNode make_cur_leaf(ByteView value_rlp);
    void reset_cur_unfolded();
    // bool split_leaf();

  public:
    GridMPT(NodeStore& node_store, bytes32 previous_root_hash) : prev_root_{previous_root_hash},
                                                                 grid_{},
                                                                 node_store_{node_store} {
        grid_.reserve(66);  // Reserve max depth to avoid reallocations
    }
    bool unfold_branch(uint8_t slot);
    void seek_with_last_insert(nibbles64& new_nibbles);
    // Main algorithm
    bytes32 calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted);
    template <typename NodeType>
    bool insert_line(uint8_t parent_slot, uint8_t parent_depth, NodeType& node);
    template <typename NodeType>
    bool cast_line(GridLine& line, NodeType& node);
};

}  // namespace silkworm::mpt