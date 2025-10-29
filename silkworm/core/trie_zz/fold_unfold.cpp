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
#include <silkworm/print.hpp>

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
template <bool DeletionEnabled>
bool GridMPT<DeletionEnabled>::unfold_node_from_rlp(ByteView rlp, uint8_t parent_slot_index, uint8_t parent_depth) {
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
        // For extensions: second contains either 32-byte hash or full RLP of embedded node
        ExtensionNode ext{nibbles64{plen, path}, {}};
        std::copy(second.cbegin(), second.cend(), ext.child.bytes);
        ext.child_len = static_cast<uint8_t>(second.size());
        insert_line(parent_slot_index, parent_depth, ext);
    }
    return true;
}

// // Folds nibbles starting from current depth_ point
// template <bool DeletionEnabled>
// inline bool GridMPT<DeletionEnabled>::fold_nibbles(int nib_count, uint8_t from_depth) {
//     // Fold till depth_ first
//     while (from_depth < grid_.size() - 1) {
//         fold_or_seek(from_depth);
//     }
//     while (nib_count > 0 && grid_.size() > 1) {
//         nib_count -= fold_back();
//         depth_--;
//     }
//     return true;
// }

// Fold the last line from the bottom and returns the number of nibbles consumed
template <bool DeletionEnabled>
uint8_t GridMPT<DeletionEnabled>::fold_back() {
    auto& grid_line = grid_.back();
    auto consumed = grid_line.consumed;

    if constexpr (DeletionEnabled) {
        // Would be called from sync_with_last_insert -> when it has common with the last deleted leaf
        if (grid_line.kind == kLeaf) {
            if (grid_line.leaf.marked_for_deletion && grid_.size() > 0) {
                GridLine& parent = grid_[grid_line.parent_depth];
                if (parent.kind == kBranch) {
                    parent.branch.delete_child(grid_line.parent_slot);
                    parent.child_depth[grid_line.parent_slot] = 0;  // clear
                    grid_.pop_back();
                    return 0;
                }
            }
        }

        if (grid_line.kind == kBranch && grid_line.branch.count == 1) {  // Should get absorbed into an extension
            // Find the non_empty child
            uint8_t non_empty_nib = 0;
            while (grid_line.branch.child_len[non_empty_nib] == 0) non_empty_nib++;
            depth_ = grid_.size() - 1;
            unfold_slot(non_empty_nib);
            ExtensionNode ext{
                nibbles64{
                    1, {non_empty_nib}}};
            cast_line(grid_line, ext);
            grid_line.child_depth[0] = depth_;
            fold_back();
        }

        if (grid_.size() > 0) {
        GridLine& parent = grid_[grid_line.parent_depth];

        // ext -> ext = ext
        if (grid_line.kind == kExt && parent.kind == kExt) {
            parent.ext.path.append(grid_line.ext.path);
            parent.ext.child = grid_line.ext.child;
            parent.ext.child_len = grid_line.ext.child_len;
            parent.child_depth[0] = 0;
            grid_.pop_back();
            return grid_line.ext.path.len;
        }

        // ext -> leaf = leaf
        if (grid_line.kind == kLeaf && parent.kind == kExt) {
            auto parent_consumed = parent.consumed;
            auto parent_depth = grid_line.parent_depth;
            nibbles64 new_path{parent.ext.path};
            new_path.append(grid_line.leaf.path);
            grid_line.parent_depth = parent.parent_depth;
            grid_line.parent_slot = parent.parent_slot;
            grid_line.leaf.path = new_path;
            grid_line.consumed = parent_consumed;       // Useful for deleted leafs on the way up
            // Copy the back element to parent position
            grid_[parent_depth] = grid_line;
            // Remove the back
            grid_.pop_back();   // remove the line whee the leaf used to be
            return consumed - parent_consumed;
        }
    }
    }

    auto node_ref = encode_line(grid_line);
    if (node_ref.size() >= 32) {
        node_ref = keccak_bytes(node_ref);
    }
    if (grid_.size() > 0) {
        auto& parent = grid_[grid_line.parent_depth];
        consumed = consumed - parent.consumed;      // 1 for br, path.len for leaf & ext
        switch (parent.kind) {
            case kBranch:
                parent.branch.set_child(grid_line.parent_slot, node_ref);
                parent.child_depth[grid_line.parent_slot] = 0;  // clear
                break;
            case kExt:
                parent.ext.set_child(node_ref);
                parent.child_depth[0] = 0;
                break;
            default:
                break;
        }
    }
    grid_.pop_back();
    return consumed;
}

// Fold n lines from the bottom
template <bool DeletionEnabled>
inline bool GridMPT<DeletionEnabled>::fold_lines(uint8_t num_lines) {
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

// Make a leaf of path after cursor of current search key
template <bool DeletionEnabled>
inline LeafNode GridMPT<DeletionEnabled>::make_cur_leaf(ByteView value_rlp) {
    LeafNode l{};
    l.parent_slot = search_nibbles_[search_nib_cursor_];
    l.path.len = 64 - (search_nib_cursor_ + 1);
    std::memcpy(l.path.nib.data(),
                &search_nibbles_[search_nib_cursor_ + 1],
                l.path.len);
    l.value = value_rlp;
    return l;
}

template <bool DeletionEnabled>
template <typename NodeType>
inline bool GridMPT<DeletionEnabled>::insert_line(uint8_t parent_slot, uint8_t parent_depth, NodeType& node) {
    if (parent_slot >= 16) return false;

    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        grid_.emplace_back(kLeaf, parent_slot, parent_depth, 64);
        grid_.back().leaf = node;
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        grid_.emplace_back(kExt, parent_slot, parent_depth, node.path.len);
        grid_.back().ext = node;
    } else {  // BranchNode
        grid_.emplace_back(kBranch, parent_slot, parent_depth, 1);
        grid_.back().branch = node;
    }
    depth_ = grid_.size() - 1;

    if (depth_ > 0) {
        if constexpr (!std::is_same_v<NodeType, LeafNode>) {
            grid_.back().consumed += grid_[parent_depth].consumed;
        }
        grid_[parent_depth].child_depth[parent_slot] = depth_;
    }
    return true;
}

template <bool DeletionEnabled>
template <typename NodeType>
// Cast a given GridLine to a node of NodeType
inline bool GridMPT<DeletionEnabled>::cast_line(GridLine& line, NodeType& node) {
    // extract parent_consumed info from existing line's consumed var
    auto parent_consumed = line.consumed;  // cumulative
    if (line.kind == kExt) {
        parent_consumed = parent_consumed - line.ext.path.len;
    } else if (line.kind == kBranch) {
        parent_consumed = parent_consumed - 1;
    } else {  // leaf
        parent_consumed = parent_consumed - line.leaf.path.len;
    }
    line.child_depth.fill(0);

    Kind kind;
    uint8_t consumed;
    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        kind = kLeaf;
        line.consumed = 64;
        line.leaf = node;
        // std::memcpy(std::addressof(line.leaf), &node, sizeof(node));
        return true;
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;
        line.ext = node;
        // std::memcpy(std::addressof(line.ext), &node, sizeof(node));
        line.consumed = consumed + parent_consumed;
        line.child_depth.fill(0);
    } else {
        kind = kBranch;
        consumed = 1;
        line.branch = node;
        // std::memcpy(std::addressof(line.branch), &node, sizeof(node));
        line.consumed = consumed + parent_consumed;
    }
    line.kind = kind;
    return true;
}

// Unfolds branch slot at depth_, returns false on error
template <bool DeletionEnabled>
inline bool GridMPT<DeletionEnabled>::unfold_slot(uint8_t slot) {
    if (slot > 15) {
        sys_println("ERROR: [unfold_slot] slot > 15 ");
    }
    if (depth_ >= grid_.size()) {
        sys_println(("ERROR: depth_=" + std::to_string(depth_) + " >= grid_.size()=" + std::to_string(grid_.size())).c_str());
        return false;
    }
    if (grid_[depth_].kind != kBranch) {
        sys_println(("ERROR: Trying to unfold_slot but grid_[" + std::to_string(depth_) + "].kind=" + std::to_string(grid_[depth_].kind) + " (not kBranch)").c_str());
        return false;
    }

    auto& grid_line = grid_[depth_];
    if (auto s = grid_line.child_depth[slot]; s) {
        if (s > grid_.size()) {
            sys_println("ERROR: child_depth > size");
        }
        depth_ = s;
        return true;
    }

    auto child_len = grid_line.branch.child_len[slot];
    if (child_len == 0) {  // empty, nothing to "unfold"
        return false;
    }
    auto& child = grid_line.branch.child[slot];
    ByteView rlp;
    if (child_len == 32) {
        // Hash ref
        rlp = node_store_.get_rlp(child);
    } else {
        rlp = ByteView{child.bytes, child_len};
    }
    if (rlp.size() == 0) {
        sys_println(("ERROR: [unfold_slot] RLP size 0, slot: " + std::to_string(slot) +
                     " child_len: " + std::to_string(child_len))
                        .c_str());
        sys_println(grid_line.branch.to_string().c_str());
        sys_println(("parent_slot: " + std::to_string(grid_line.parent_slot) +
                     " parent_depth: " + std::to_string(grid_line.parent_depth))
                        .c_str());
        sys_println(("requested RLP for hash: " + to_hex(child.bytes)).c_str());
        sys_println(grid_to_string().c_str());
    }
    bool success = unfold_node_from_rlp(rlp, slot, depth_);
    if (success)
        grid_line.child_depth[slot] = depth_;
    return success;
}

}  // namespace silkworm::mpt
