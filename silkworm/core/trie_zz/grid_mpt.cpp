// #pragma once  // Commented out since this is compiled as a .cpp file
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/encode.hpp>

#include "helpers.hpp"
#include "mpt.hpp"
// #include "rlp.hpp"
#include <silkworm/core/common/empty_hashes.hpp>

#include "rlp_sw.hpp"

namespace silkworm::mpt {

// Decode node from hash into a GridLine and push onto grid
bool GridMPT::unfold_node_from_hash(const bytes32& hash, uint8_t parent_slot_index, uint8_t parent_depth) {
    // branch by default, change later
    grid_.emplace_back(kBranch, parent_slot_index, parent_depth, 1);
    GridLine& grid_line = grid_.back();
    grid_line.hash = hash;

    ByteView rlp = node_store_.get_rlp(hash);

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
        grid_line.consumed = plen;
    } else {
        if (second.size() != 32) return false;  // we store child as hash
        grid_line.kind = kExt;
        grid_line.ext.path.len = plen;
        std::memcpy(grid_line.ext.path.nib.data(), path.data(), plen);
        std::memcpy(grid_line.ext.child.bytes, second.data(), 32);
        grid_line.consumed = plen;
    }
    grid_line.consumed += grid_[parent_depth].consumed;
    return true;
}

// Encode and hash the given line and store it
inline void hash_line(GridLine& line) {
    Bytes encoded;
    switch (line.kind) {
        case kBranch:
            encoded = encode_branch(line.branch);
            break;
        case kExt:
            encoded = encode_ext(line.ext);
            break;
        case kLeaf:
            encoded = encode_leaf(line.leaf);
            break;
    }
    line.hash = keccak_bytes(encoded);
}

// Folds nibbles starting from current depth_ point
inline bool GridMPT::fold_nibbles(int nib_count) {
    // Fold till depth_ first
    while (depth_ < grid_.size() - 1) {
        fold_back();
    }
    while (nib_count > 0) {
        nib_count -= fold_back();
    }
    return true;
}

// Fold the last line from the bottom and returns the number of nibbles consumed
inline uint8_t GridMPT::fold_back() {
    auto grid_line = grid_.back();  // Get the last element
    grid_.pop_back();               // Remove it from the vector
    auto consumed = grid_line.consumed;
    hash_line(grid_line);
    if (grid_.size() > 0) {
        auto& parent = grid_[grid_line.parent_depth];
        consumed = consumed - parent.consumed;
        switch (parent.kind) {
            case kBranch:
                parent.branch.child[grid_line.parent_slot] = grid_line.hash;
                break;
            case kExt:
                parent.ext.child = grid_line.hash;
                break;
            default:
                break;
        }
    }
    return consumed;
}

// Fold n lines from the bottom
inline bool GridMPT::fold_lines(uint8_t num_lines) {
    while (num_lines) {
        auto grid_line = grid_.back();  // Get the last element
        grid_.pop_back();               // Remove it from the vector
        hash_line(grid_line);
        if (depth_ > 0) {
            --depth_;
            auto& parent = grid_[grid_line.parent_depth];
            switch (parent.kind) {
                case kBranch:
                    parent.branch.child[grid_line.parent_slot] = grid_line.hash;
                    break;
                case kExt:
                    parent.ext.child = grid_line.hash;
                    break;
                default:
                    break;
            }
        } else {
            return false;
        }
        --num_lines;
    }
    return true;
}

// Create a leaf for remaining key suffix (after consuming one child nibble already if needed)
inline bytes32 GridMPT::make_leaf_for_suffix(const uint8_t* suffix, uint8_t len, ByteView value) {
    LeafNode l{};
    l.path.len = len;
    if (len) std::memcpy(l.path.nib.data(), suffix, len);
    l.value = value;
    Bytes enc = encode_leaf(l);
    bytes32 h = keccak_bytes(enc);
    if (node_store_.put_rlp) node_store_.put_rlp(h, enc);
    return h;
}

// Make a leaf of path after cursor of current search key
inline LeafNode GridMPT::make_cur_leaf(ByteView value_rlp) {
    LeafNode l{};
    l.path.len = 64 - (search_nib_cursor_ + 1);
    std::memcpy(l.path.nib.data(),
                &search_nibbles_[search_nib_cursor_ + 1],
                l.path.len);
    l.value = value_rlp;
    l.parent_slot = search_nibbles_[search_nib_cursor_];
    return l;
}

// Define traits to map types to kinds
template<typename T> struct NodeTraits;

template<> struct NodeTraits<LeafNode> {
    static constexpr Kind kind = kLeaf;
    static constexpr uint8_t consumed = 64;
};

template<> struct NodeTraits<ExtensionNode> {
    static constexpr Kind kind = kExt;
    static constexpr bool needs_parent_consumed = true;
    static constexpr bool updates_unfolded = false;
};

template<> struct NodeTraits<BranchNode> {
    static constexpr Kind kind = kBranch;
    static constexpr bool needs_parent_consumed = true;
    static constexpr bool updates_unfolded = false;
};

template<typename NodeType>
inline bool GridMPT::insert_line(uint8_t parent_slot, uint8_t parent_depth, NodeType& node) {
    if (parent_slot >= 16) return false;
    
    if (cur_unfold_branch_ != parent_depth) {
        std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
        cur_unfold_branch_ = parent_depth;
    }
    
    Kind kind;
    uint8_t consumed;
    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        kind = kLeaf;
        consumed = 64;
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;
    } else {
        kind = kBranch;
        consumed = 1;
    }
    
    grid_.emplace_back(kind, parent_slot, parent_depth, consumed);
    depth_ = grid_.size() - 1;
    
    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        std::memcpy(&grid_[depth_].leaf, &node, sizeof(LeafNode));
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        std::memcpy(&grid_[depth_].ext, &node, sizeof(ExtensionNode));
        if (depth_ != parent_depth) {
            grid_[depth_].consumed += grid_[parent_depth].consumed;
        }
    } else {  // BranchNode
        std::memcpy(&grid_[depth_].branch, &node, sizeof(BranchNode));
        if (depth_ != parent_depth) {
            grid_[depth_].consumed += grid_[parent_depth].consumed;
        }
    }
    unfolded_child_[parent_slot] = depth_;
    return true;
}

template<typename NodeType>
inline bool GridMPT::cast_line(GridLine line, NodeType& node){
    Kind kind;
    uint8_t consumed;
    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        kind = kLeaf;
        consumed = 64;
        std::memcpy(std::addressof(line.leaf), &node, sizeof(node))
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;
        std::memcpy(std::addressof(line.ext), &node, sizeof(node))
    } else {
        kind = kBranch;
        consumed = 1;
        std::memcpy(std::addressof(line.branch), &node, sizeof(node))
    }

    auto parent_consumed = line.consumed;
    if (line.kind == kExt){
        parent_consumed -= line.ext.path.len;
    } else if (line.kind == kBranch){
        parent_consumed -= 1;
    } else {
        parent_consumed = 0;
    }
    std::memcpy(std::addressof(line), &node, sizeof(node));
    line.consumed = consumed + parent_consumed;
    return true;
}

// // Inserts leaf at current depth
// inline bool GridMPT::insert_line(uint8_t parent_slot, uint8_t parent_depth, LeafNode& leaf) {
//     if (parent_slot >= 16) {
//         return false;
//     }
//     if (cur_unfold_branch_ != parent_depth) {
//         std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
//         cur_unfold_branch_ = parent_depth;
//     }
//     grid_.emplace_back(kLeaf, parent_slot, parent_depth, 64);
//     depth_ = grid_.size() - 1;
//     std::memcpy(std::addressof(grid_[depth_].leaf), &leaf, sizeof(LeafNode));
//     unfolded_child_[parent_slot] = depth_;
//     return true;
// }

// // Inserts extension at current depth_
// inline bool GridMPT::insert_line(uint8_t parent_slot, uint8_t parent_depth, ExtensionNode& ext) {
//     if (parent_slot >= 16) {
//         return false;
//     }
//     if (cur_unfold_branch_ != parent_depth) {
//         std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
//         cur_unfold_branch_ = parent_depth;
//     }
//     grid_.emplace_back(kExt, parent_slot, parent_depth, ext.path.len);
//     depth_ = grid_.size() - 1;
//     std::memcpy(std::addressof(grid_[depth_].ext), &ext, sizeof(ExtensionNode));
//     if (depth_ != parent_depth) {
//         grid_[depth_].consumed += grid_[parent_depth].consumed;
//     }
//     return true;
// }

// // Inserts branch at current depth_
// inline bool GridMPT::insert_line(uint8_t parent_slot, uint8_t parent_depth, BranchNode& bn) {
//     if (parent_slot >= 16) {
//         return false;
//     }
//     if (cur_unfold_branch_ != parent_depth) {
//         std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
//         cur_unfold_branch_ = parent_depth;
//     }
//     grid_.emplace_back(kBranch, parent_slot, parent_depth, 1);
//     depth_ = grid_.size() - 1;
//     std::memcpy(std::addressof(grid_[depth_].branch), &bn, sizeof(BranchNode));
//     if (depth_ != parent_depth) {
//         grid_[depth_].consumed += grid_[parent_depth].consumed;
//     }
//     return true;
// }

// Unfold from root as we traverse through the list of account updates
// Finally return the root
bytes32 GridMPT::calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted) {
    if (prev_root == kEmptyRoot) {
        depth_ = 0;
        grid_[depth_].kind = kLeaf;
        grid_[depth_].consumed = 0;
        grid_[depth_].parent_depth = 0;
    } else {
        // Load root on to first line
        unfold_node_from_hash(prev_root, 0, 0);
    }

    for (auto trie_upd : updates_sorted) {
        auto new_nibbles = nibbles64::from_bytes32(trie_upd.key);

        if (search_nibbles_.len > 0 && grid_.size() > 1) {
            // Previous leaf exists in a branch
            // Find the least common path (from the top) with the last inserted key's nibbles as reference
            // The last leaf must have been inserted to a branch
            // If lcp == consumed, the new leaf shares path, have to split
            // if lcp == consumed - 1, fold the leaf
            // if lcp < consumed - 1, fold the leaf line and more nibbles
            size_t lcp = 0;
            auto& parent_depth = grid_[depth_].parent_depth;
            while (new_nibbles[lcp] == search_nibbles_[lcp] && lcp < grid_[parent_depth].consumed) ++lcp;
            int fold_for = grid_[parent_depth].consumed - lcp;

            if (fold_for == 0) {
                search_nib_cursor_ = grid_[parent_depth].consumed;
            } else {
                fold_back();            // fold the last leaf
                depth_ = parent_depth;  // Set the cursor to parent and fold from here
                if (!fold_nibbles(fold_for - 1)) {
                    return bytes32{};
                }
                search_nib_cursor_ = grid_[depth_].consumed - 1;
                std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
            }
        }

        search_nibbles_ = new_nibbles;

        while (depth_ < 64) {  // Searching down
            auto& grid_line = grid_[depth_];
            if (grid_line.consumed == 0) {  // Empty trie
                auto l = make_cur_leaf(trie_upd.value_rlp);
                insert_line(l.path[0], 0, l);
                break;
            }
            if (grid_line.kind == kBranch) {
                auto nib = search_nibbles_[search_nib_cursor_];
                if (unfolded_child_[nib]) {  // If child here was unfolded previously
                    depth_ = unfolded_child_[nib];
                } else {
                    auto child = grid_line.branch.child[nib];
                    if (is_zero(child)) {
                        // insert
                        auto l = make_cur_leaf(trie_upd.value_rlp);
                        insert_line(l.parent_slot, depth_, l);
                        break;
                    } else {
                        unfold_node_from_hash(child, nib, depth_);
                        search_nib_cursor_++;
                        continue;
                    }
                }
                auto& h_at_branch_slot = grid_line.branch.child[grid_line.parent_slot];
                if (is_zero(h_at_branch_slot)) {
                    // insert
                    auto l = make_cur_leaf(trie_upd.value_rlp);
                    insert_line(l.parent_slot, depth_, l);
                    break;
                } else {
                    unfold_node_from_hash(h_at_branch_slot, search_nibbles_[search_nib_cursor_], depth_ - 1);
                    search_nib_cursor_++;
                    continue;
                }
            } else if (grid_line.kind == kExt) {
                // go down till the first divergence point
                uint8_t m = 0;
                while (m < grid_line.ext.path.len && (search_nib_cursor_ + m) < 64 && grid_line.ext.path[m] == search_nibbles_[search_nib_cursor_ + m])
                    ++m;
                search_nib_cursor_ += m;

                if (m == grid_line.ext.path.len) {
                    // Full match -> continue below
                    ++depth_;
                    unfold_node_from_hash(grid_line.ext.child, search_nibbles_[search_nib_cursor_], depth_ - 1);
                    continue;
                } else {
                    // We will now insert branch at divergence point
                    // Note: m is at the point of divergence
                    BranchNode bn{};
                    auto old_ext{grid_line.ext};
                    auto ext_path_len = old_ext.path.len;

                    if (m > 0) {
                        // Shorten the grid_line current extension till the divergence point
                        grid_line.ext.path.len = m;
                        grid_line.ext.child = bytes32{};  // Update later with the created branch

                        // insert branch after the shortened extension and mark its parent as it
                        insert_line(0, depth_, bn);
                        grid_line = grid_[depth_];
                    } else {
                        // Extension replaced by branch
                        cast_line(grid_line, bn);
                        // grid_line.kind = kBranch;
                        // std::memcpy(std::addressof(grid_line.branch), &bn, sizeof(bn));
                    }
                    // ============================================
                    // len = m consumed by the extension node, after update
                    // len = 1 consumed by the new branch node
                    // len = old_ext.path.len - m - 1 consumed by extension node created after
                    // ============================================
                    ext_path_len = ext_path_len - m - 1;
                    if (ext_path_len > 0) {
                        // Insert an extension node for the remainder of extension after the branch
                        ExtensionNode ext_mplus1{};
                        ext_mplus1.path.len = ext_path_len;
                        std::memcpy(ext_mplus1.path.nib.data(),
                                    old_ext.path.nib.data() + m + 1,
                                    ext_mplus1.path.len);
                        ext_mplus1.child = old_ext.child;
                        insert_line(old_ext.path[m], depth_, ext_mplus1);
                        --depth_;   // set it to the branch
                    } else {
                        // The extension is absorbed or not needed, so put the child directly into the newly created bn
                        grid_line.branch.child[old_ext.path[m]] = old_ext.child;
                    }
                    auto search_key_leaf = make_cur_leaf(trie_upd.value_rlp);
                    insert_line(search_key_leaf.parent_slot, depth_, search_key_leaf);
                    break;  // insertion complete
                }
            } else {  // it's a leaf
                BranchNode bn{};
                // Find common path and create extension and push
                size_t i = 0;
                while (grid_line.leaf.path[i] == search_nibbles_[search_nib_cursor_ + i] && i < grid_line.leaf.path.len && search_nib_cursor_ + i < 64) ++i;
                if (search_nib_cursor_ + i == 64) {  // This path exists in the tree already, update the value and fold
                    grid_line.leaf.value = trie_upd.value_rlp;
                    break;  // update complete
                } else if (i > 0) {
                    nibbles64 common_path{};
                    std::memcpy(common_path.nib.data(), grid_line.leaf.path.nib.data(), i);
                    common_path.len = i;
                    ExtensionNode ext_common{};
                    ext_common.path = common_path;
                    ext_common.child = bytes32{};  // update while folding with the branch node created below
                    search_nib_cursor_ += i;

                    // Have to re-hash the existing leaf
                    bn.child[grid_line.leaf.path[i]] = make_leaf_for_suffix(
                        &grid_line.leaf.path[i + 1],
                        grid_line.leaf.path.len - (i + 1),
                        grid_line.leaf.value);
                    insert_line(ext_common);
                    ++depth_;
                } else {
                    // re-use the hash
                    bn.child[grid_line.leaf.path[i]] = grid_line.hash;
                }
                insert_line(bn, search_nibbles_[search_nib_cursor_]);
                auto l = make_cur_leaf(trie_upd.value_rlp);
                ++depth_;

                insert_line(l.parent_slot, l);
                break;  // insertion complete
            }
        }
    }

    // Fold till root
    if (!fold_lines(depth_)) {
        return bytes32{};
    }
    hash_line(grid_[0]);  // re-calculate root's hash
    return grid_[0].hash;
}

}  // namespace silkworm::mpt
