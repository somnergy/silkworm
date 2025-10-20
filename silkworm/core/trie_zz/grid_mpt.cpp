// #pragma once  // Commented out since this is compiled as a .cpp file
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>

#include "helpers.hpp"
#include "mpt.hpp"
#include "rlp_sw.hpp"

// Here lies an optimized code for stateless Merkle Patricia Trie
// The core idea is processing nodes in a stack/grid where
// a node is inserted, processed and moved on to the next slot/node
// The core idea is based on the fact that if updates are sorted
// by keys, you never have to visit the left sub-tree at any height
// of any branch once you are done processing that.
namespace silkworm::mpt {

// Decode node from hash into a GridLine and push onto grid
bool GridMPT::unfold_node_from_rlp(ByteView rlp, uint8_t parent_slot_index, uint8_t parent_depth) {
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
            return insert_line(parent_slot_index, parent_depth, tmp);
        }
    }
    // Else extension/leaf:
    bool is_leaf = false;
    std::array<uint8_t, 64> path{};
    uint8_t plen = 0;
    ByteView second{};

    if (!decode_ext_or_leaf(*list, is_leaf, path, plen, second)) return false;
    if (is_leaf) {
        LeafNode l{nibbles64{plen, path}, parent_slot_index, second};
        insert_line(parent_slot_index, parent_depth, l);
    } else {
        if (second.size() != 32) return false;  // we store child as hash
        ExtensionNode ext{nibbles64{plen, path}, {}};
        std::copy(second.cbegin(), second.cend(), ext.child.bytes);
        insert_line(parent_slot_index, parent_depth, ext);
    }
    return true;
}

// Encode the given line's node
inline Bytes encode_line(GridLine& line) {
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
    return encoded;
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

    auto node_ref = encode_line(grid_line);
    if (node_ref.size() >= 32) {
        node_ref = keccak_bytes(node_ref);
    }

    auto consumed = grid_line.consumed;
    if (grid_.size() > 0) {
        auto& parent = grid_[grid_line.parent_depth];
        consumed = consumed - parent.consumed;
        switch (parent.kind) {
            case kBranch:
                parent.branch.set_child(grid_line.parent_slot, node_ref);
                break;
            case kExt:
                parent.ext.set_child(node_ref);
                break;
            default:
                break;
        }
    }
    return consumed;
}

// Fold n lines from the bottom
inline bool GridMPT::fold_lines(uint8_t num_lines) {
    depth_ = grid_.size() - 1;
    if (num_lines > depth_) {
        return false;
    }
    while (num_lines) {
        fold_back();
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
    node_store_.put_rlp(h, enc);
    return h;
}

// Make a leaf of path after cursor of current search key
inline LeafNode GridMPT::make_cur_leaf(ByteView value_rlp) {
    LeafNode l{};
    l.parent_slot = search_nibbles_[search_nib_cursor_];
    l.path.len = 64 - (search_nib_cursor_ + 1);
    std::memcpy(l.path.nib.data(),
                &search_nibbles_[search_nib_cursor_ + 1],
                l.path.len);
    l.value = value_rlp;
    return l;
}

void GridMPT::reset_cur_unfolded() {
    std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
}

template <typename NodeType>
inline bool GridMPT::insert_line(uint8_t parent_slot, uint8_t parent_depth, NodeType& node) {
    if (parent_slot >= 16) return false;

    if (cur_unfold_depth_ != parent_depth) {
        std::memset(unfolded_child_.data(), 0, sizeof(unfolded_child_));
        cur_unfold_depth_ = parent_depth;
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

template <typename NodeType>
// Cast a given GridLine to a node of NodeType
inline bool GridMPT::cast_line(GridLine& line, NodeType& node) {
    Kind kind;
    uint8_t consumed;
    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        kind = kLeaf;
        consumed = 64;
        std::memcpy(std::addressof(line.leaf), &node, sizeof(node));
        return true;
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;
        std::memcpy(std::addressof(line.ext), &node, sizeof(node));
    } else {
        kind = kBranch;
        consumed = 1;
        std::memcpy(std::addressof(line.branch), &node, sizeof(node));
    }

    // extract parent_consumed info from existing line's consumed var
    auto parent_consumed = line.consumed;  // cumulative
    if (line.kind == kExt) {
        parent_consumed = parent_consumed - line.ext.path.len;
    } else if (line.kind == kBranch) {
        parent_consumed = parent_consumed - 1;
    } else [[unlikely]] {  // leaf
        parent_consumed = 0;
    }
    line.kind = kind;
    line.consumed = consumed + parent_consumed;
    return true;
}

// Unfolds branch slot at depth_, returns false on error
inline bool GridMPT::unfold_branch(uint8_t slot) {
    if (unfolded_child_[slot]) {  // If child here was unfolded previously
        depth_ = unfolded_child_[slot];
        return true;
    }
    auto child_len = grid_[depth_].branch.child_len[slot];
    if (child_len < 2) {  // empty, nothing to "unfold"
        return false;
    }
    auto child = grid_[depth_].branch.child[slot];
    ByteView rlp;
    if (child_len >= 32) {
        rlp = node_store_.get_rlp(child);
    } else {
        rlp = ByteView{child.bytes, child_len};
    }

    unfold_node_from_rlp(rlp, slot, depth_);
    unfolded_child_[slot] = depth_;
    return true;
}

// Unfold from root as we traverse through the list of account updates
// Finally return the root
bytes32 GridMPT::calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted) {
    if (prev_root_ != kEmptyRoot) {
        // Load root on to first line
        auto rlp = node_store_.get_rlp(prev_root_);
        unfold_node_from_rlp(rlp, 0, 0);
    }

    for (auto trie_upd : updates_sorted) {
        auto new_nibbles = nibbles64::from_bytes32(trie_upd.key);

        if (search_nibbles_.len > 0 && grid_.size() > 1) {
            // Previous leaf exists, and it's in a branch
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
        search_nibbles_ = new_nibbles;      // TODO: Copy or Ref???
        if (grid_[depth_].consumed == 0) {  // Empty trie
            LeafNode l{search_nibbles_, 0, trie_upd.value_rlp};
            insert_line(0, 0, l);
            continue;  // to the next update
        }
        while (depth_ < 64) {  // Searching down
            if (grid_[depth_].kind == kBranch) {
                auto nib = search_nibbles_[search_nib_cursor_];
                if (!unfold_branch(nib)) {
                    // Child is empty
                    auto l = make_cur_leaf(trie_upd.value_rlp);
                    insert_line(l.parent_slot, depth_, l);
                    break;
                }
                continue;
            } else if (grid_[depth_].kind == kExt) {
                // go down till the first divergence point
                uint8_t m = 0;
                while (m < grid_[depth_].ext.path.len && (search_nib_cursor_ + m) < 64 && grid_[depth_].ext.path[m] == search_nibbles_[search_nib_cursor_ + m])
                    ++m;
                search_nib_cursor_ += m;

                if (m == grid_[depth_].ext.path.len) {
                    // Full match -> continue below
                    ++depth_;
                    ByteView rlp;
                    if (grid_[depth_].ext.child_len < 32) {
                        rlp = ByteView{grid_[depth_].ext.child.bytes, grid_[depth_].ext.child_len};
                    } else {
                        rlp = node_store_.get_rlp(grid_[depth_].ext.child);
                    }
                    unfold_node_from_rlp(rlp, search_nibbles_[search_nib_cursor_], depth_ - 1);
                    continue;
                } else {
                    // We will now insert branch at the divergence point
                    // Note: m is at the point of divergence
                    BranchNode bn{};
                    auto old_ext{grid_[depth_].ext};
                    auto ext_path_len = old_ext.path.len;

                    if (m > 0) {
                        // Shorten the grid_line current extension till the divergence point
                        grid_[depth_].ext.path.len = m;
                        grid_[depth_].ext.child = bytes32{};  // Update later with the created branch
                        // insert branch after the shortened extension and mark its parent as it
                        insert_line(0, depth_, bn);
                    } else {
                        // Extension replaced by branch
                        cast_line(grid_[depth_], bn);
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
                        ext_mplus1.child_len = old_ext.child_len;
                        auto d = depth_;
                        insert_line(old_ext.path[m], depth_, ext_mplus1);
                        if (old_ext.path[m] < search_nibbles_[search_nib_cursor_]) {
                            fold_back();  // Don't need to deal with left side nibbles in next iterations
                        } else {
                            depth_ = d;  // set it to the branch
                        }
                    } else {
                        // The extension is absorbed or not needed, so put the child directly into the newly created bn
                        grid_[depth_].branch.child[old_ext.path[m]] = old_ext.child;
                        grid_[depth_].branch.child_len[old_ext.path[m]] = old_ext.child_len;
                    }
                    auto l = make_cur_leaf(trie_upd.value_rlp);
                    insert_line(l.parent_slot, depth_, l);
                    break;  // insertion complete
                }
            } else {
                // It's a leaf:
                // Find common path and create extension and push
                // Note: grid_line.leaf.path.len == (64 - search_nib_cursor_)

                size_t cp = 0;
                while (grid_[depth_].leaf.path[cp] == search_nibbles_[search_nib_cursor_ + cp] && cp < grid_[depth_].leaf.path.len) ++cp;
                if (search_nib_cursor_ + cp == 64) {  // This path exists, update the value
                    grid_[depth_].leaf.value = trie_upd.value_rlp;
                    break;  // update complete
                }

                // Cache the value before splitting
                LeafNode old_leaf{grid_[depth_].leaf};
                BranchNode bn{};

                if (cp > 0) {  // Need to put an extension before the branch
                    ExtensionNode ext_common{};
                    std::memcpy(ext_common.path.nib.data(), grid_[depth_].leaf.path.nib.data(), cp);
                    ext_common.path.len = cp;

                    // Make the line an extension and insert a branch with this extension as the parent
                    cast_line(grid_[depth_], ext_common);
                    search_nib_cursor_ += cp;
                    insert_line(0, depth_, bn);  // sets the depth_ at the branch after

                    old_leaf.path.len = old_leaf.path.len - cp - 1;  // cp: extension, 1: branch
                    old_leaf.parent_slot = old_leaf.path[cp];
                } else {
                    // Make the line a branch
                    cast_line(grid_[depth_], bn);
                    old_leaf.parent_slot = old_leaf.path[0];
                    old_leaf.path.len -= 1;
                }
                // Shift the nibble array left by cp + 1
                if (old_leaf.path.len > 0) {
                    std::memmove(old_leaf.path.nib.data(),
                                 old_leaf.path.nib.data() + cp + 1,
                                 static_cast<size_t>(old_leaf.path.len));
                }
                // Insert the leaves to the branch (which is at depth_ now) as parent
                auto l = make_cur_leaf(trie_upd.value_rlp);  // sets parent_slot too at l, with first nib
                if (old_leaf.parent_slot > l.parent_slot) {  // ordering
                    insert_line(old_leaf.parent_slot, depth_, old_leaf);
                    insert_line(l.parent_slot, depth_ - 1, l);
                } else {
                    insert_line(l.parent_slot, depth_, l);
                    insert_line(old_leaf.parent_slot, depth_ - 1, old_leaf);
                    fold_back();  // No need to keep the left nib
                }

                break;  // insertion complete
            }
        }
    }

    // Fold till root
    if (!fold_lines(grid_.size() - 1)) {
        return bytes32{};
    }
    auto encoded = encode_line(grid_[0]);
    // std::cout << "calc_root encoded branch: " << silkworm::to_hex(encoded) << std::endl;
    return keccak_bytes(encoded);
}

}  // namespace silkworm::mpt
