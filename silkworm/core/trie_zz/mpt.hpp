#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/print.hpp>

#include "node_store_i.hpp"

namespace silkworm {
using bytes32 = evmc::bytes32;
inline bytes32 keccak_bytes(const ByteView x) {
    return std::bit_cast<bytes32>(ethash_keccak256(x.data(), x.size()).bytes);
}
inline bytes32 keccak_bytes32(const bytes32& x) {
    return std::bit_cast<bytes32>(ethash_keccak256_32(x.bytes));
}
}  // namespace silkworm

namespace silkworm::mpt {

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

    // Append another nibbles64 object to this one
    void append(const nibbles64& other) {
        uint8_t copy_len = other.len;
        if (len + copy_len > 64) {
            copy_len = 64 - len;  // Don't overflow
        }
        std::memcpy(&nib[len], other.nib.data(), copy_len);
        len += copy_len;
    }

    // Debug: Print nibbles as hex (lower 4 bits only)
    std::string to_string() const {
        std::string result = "[len=" + std::to_string(static_cast<int>(len)) + "]: ";
        for (uint8_t i = 0; i < len; i++) {
            uint8_t nibble = nib[i] & 0x0F;
            char hex = nibble < 10 ? ('0' + nibble) : ('a' + nibble - 10);
            result += hex;
        }
        return result;
    }
};

struct BranchNode {
    alignas(32) std::array<bytes32, 16> child{};
    std::array<uint8_t, 16> child_len{};
    uint16_t mask{};
    uint8_t count{};   // number of non-empty children
    ByteView value{};  // RLP "value" payload view (empty if none)

    // Quick bit operations on mask
    inline uint8_t count_zero_bits() const {
        return 16 - static_cast<uint8_t>(std::popcount(mask));
    }

    inline uint8_t single_bit_position() const {
        // Returns position (0-15) if exactly one bit is set
        // Undefined if mask has 0 or >1 bits set
        return static_cast<uint8_t>(std::countr_zero(mask));
    }

    inline bool has_single_bit() const {
        return mask != 0 && (mask & (mask - 1)) == 0;  // Check if power of 2
    }

    // Explicit constructor to ensure zero-initialization
    BranchNode() {
        child = {};
        child_len = {};
        mask = 0;
        count = 0;
        value = ByteView{};
    }

    // sets the branch's child at the slot with b.size() <= 32
    inline void set_child(uint8_t slot, ByteView b) {
        if (child_len[slot] == 0) {
            ++count;
            mask |= 1 << slot;
        }
        std::memcpy(child[slot].bytes, b.data(), b.size());
        child_len[slot] = static_cast<uint8_t>(b.size());
    }

    inline void delete_child(uint8_t slot) {
        child_len[slot] = 0;
        count = count ? count - 1 : 0;
        mask ^= (1 << slot);
    }

    std::string to_string() const {
        std::string result = "BranchNode children:\n";
        for (uint8_t i = 0; i < 16; i++) {
            if (child_len[i] > 0) {
                result += "  [" + std::to_string(i) + "] len=" + std::to_string(child_len[i]) +
                          " hash=" + to_hex(child[i].bytes) + "\n";
            }
        }
        return result;
    }
};

struct ExtensionNode {
    nibbles64 path;
    bytes32 child{};
    uint8_t child_len;

    inline void set_child(ByteView b) {
        std::memcpy(child.bytes, b.data(), b.size());
        child_len = static_cast<uint8_t>(b.size());
    }

    std::string to_string() const {
        std::string result = "ExtensionNode:\n";
        result += "  " + path.to_string() + "\n";
        result += "  child_len=" + std::to_string(child_len) +
                  " child_hash=" + to_hex(child.bytes) + "\n";
        return result;
    }
};

struct LeafNode {
    nibbles64 path;
    uint8_t parent_slot;
    ByteView value{};
    bool marked_for_deletion{false};

    std::string to_string() const {
        std::string result = "LeafNode:\n";
        result += "  parent_slot=" + std::to_string(parent_slot) + "\n";
        result += "  " + path.to_string() + "\n";
        result += "  value_len=" + std::to_string(value.size());
        if (marked_for_deletion) result += " [MARKED FOR DELETION]";
        result += "\n";
        return result;
    }
};

inline bool is_zero_quick(const bytes32& h) {
    auto words = std::bit_cast<std::array<std::uint32_t, 8>>(h);
    return (words[0] | words[1] | words[2] | words[3] |
            words[4] | words[5] | words[6] | words[7]) == 0;
}
// inline bool is_zero_quick(const Bytes& b) {
//     return std::all_of(b.begin(), b.end(), [](uint8_t byte) { return byte == 0; });
// }
inline bool is_zero_quick(const ByteView b) {
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
    std::array<uint8_t, 16> child_depth{};

    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };

    GridLine() : kind(kBranch), parent_slot(0), parent_depth(0), consumed(0), branch{} {}
    GridLine(uint8_t k, uint8_t pslot, uint8_t pdepth, uint8_t c) : kind{k}, parent_slot{pslot}, parent_depth{pdepth}, consumed{c} {}

    std::string to_string() const {
        std::string kind_str = (kind == kBranch) ? "Branch" : (kind == kExt) ? "Extension"
                                                                             : "Leaf";
        std::string result = "GridLine [" + kind_str + "]:\n";
        result += "  parent_slot=" + std::to_string(parent_slot) +
                  " parent_depth=" + std::to_string(parent_depth) +
                  " consumed=" + std::to_string(consumed) + "\n";

        // Show non-zero child depths
        bool has_children = false;
        for (uint8_t i = 0; i < 16; i++) {
            if (child_depth[i] != 0) {
                if (!has_children) {
                    result += "  child_depths: ";
                    has_children = true;
                }
                result += "[" + std::to_string(i) + "]=" + std::to_string(child_depth[i]) + " ";
            }
        }
        if (has_children) result += "\n";

        // Add node-specific details
        if (kind == kBranch) {
            result += "  " + branch.to_string();
        } else if (kind == kExt) {
            result += "  " + ext.to_string();
        } else {
            result += "  " + leaf.to_string();
        }
        return result;
    }
};

struct TrieNodeFlat {
    bytes32 key;
    Bytes value_rlp;

    // Lexicographic comparison for sorting
    bool operator<(const TrieNodeFlat& other) const {
        return key < other.key;
    }
};

// A class holding the data for the Trie root calculation
// Proceeds as follows:
// Search a key by going down the tree (unfolding)
// When you find a position to insert, insert there and
// recalulcate the hash of that node all the way up (folding)
// If there are more keys to insert, find a common divergence point
// and insert the new key there before folding further.
// More unfolding and folding needed for this or more keys
template <bool DeletionEnabled = false>
class GridMPT {
    uint8_t depth_{0};              // The current depth we are visiting
    uint8_t search_nib_cursor_{0};  // The position in the current search key
    // Previous root of the trie
    bytes32 prev_root_;
    // A stack of grid-lines consisting of TrieNodes
    std::vector<GridLine> grid_;
    nibbles64 search_nibbles_;  // The current key being searched for/inserted

    // Flags
    bool should_unfold_{false};
    bool should_fold_{false};
    bool is_searching_{false};

    // A store containing the set of keys to be inserted
    NodeStore& node_store_;

    // Helper methods
    bool unfold_node_from_rlp(ByteView rlp, uint8_t parent_slot_index, uint8_t parent_depth);
    void fold_back();
    LeafNode make_cur_leaf(ByteView value_rlp);

  public:
    GridMPT(NodeStore& node_store, bytes32 previous_root_hash)
        : prev_root_{previous_root_hash},
          grid_{},
          node_store_{node_store} {
        grid_.reserve(66);  // Reserve max depth to avoid reallocations
        if (previous_root_hash != kEmptyRoot) {
            // Load root on to first line
            auto rlp = node_store.get_rlp(previous_root_hash);
            unfold_node_from_rlp(rlp, 0, 0);

            // === DEBUG =====
            // sys_println(grid_to_string().c_str());
            ///
        }
    }

    bool unfold_slot(uint8_t slot);
    void fold_children(uint8_t parent_depth);
    void seek_with_last_insert(nibbles64& new_nibbles);

    // Main algorithm
    bytes32 calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted);

    template <typename NodeType>
    bool insert_line(uint8_t parent_slot, uint8_t parent_depth, NodeType& node);

    template <typename NodeType>
    bool cast_line(GridLine& line, NodeType& node);

    uint8_t consumed_nibbles(GridLine& line);

    // Compile-time check for deletion support
    static constexpr bool supports_deletion() { return DeletionEnabled; }

    // Debug: print entire grid state
    std::string grid_to_string() const {
        std::string result = "=== GridMPT State ===\n";
        result += "depth=" + std::to_string(depth_) +
                  " search_nib_cursor=" + std::to_string(search_nib_cursor_) +
                  " grid_size=" + std::to_string(grid_.size()) + "\n";
        result += "prev_root=" + to_hex(prev_root_.bytes) + "\n";
        result += "search_nibbles_=" + search_nibbles_.to_string() + "\n";

        result += "\n--- Grid Lines ---\n";
        for (size_t i = 0; i < grid_.size(); i++) {
            result += "Line[" + std::to_string(i) + "]";
            if (i == depth_) result += " <-- current depth";
            result += ":\n" + grid_[i].to_string();
            result += "\n";
        }
        result += "==================\n";
        return result;
    }
};

}  // namespace silkworm::mpt