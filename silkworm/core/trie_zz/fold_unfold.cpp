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

template <bool DeletionEnabled>
void GridMPT<DeletionEnabled>::delete_leaf(uint8_t depth) {
    GridLine& grid_line = grid_[depth];
    GridLine& parent = grid_[grid_line.parent_depth];
    uint8_t parent_slot = grid_line.parent_slot;
    if (depth != grid_.size() - 1 && grid_.size() > 0 && parent.kind == kBranch && grid_.back().parent_depth == grid_line.parent_depth) {
        grid_line = grid_.back();   // Move the last child here
    }
    parent.branch.delete_child(parent_slot);
    parent.child_depth[parent_slot] = 0;  // clear
    grid_.pop_back();
}

// Fold the last line from the bottom and returns the number of nibbles consumed
template <bool DeletionEnabled>
void GridMPT<DeletionEnabled>::fold_back() {
    auto& grid_line = grid_.back();

    if constexpr (DeletionEnabled) {

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


            if (parent.kind == kBranch && parent.branch.count == 1) {
                // Find the non_empty child
                uint8_t non_empty_nib = 0;
                while (parent.branch.child_len[non_empty_nib] == 0) non_empty_nib++;  // TODO: use bit manipulation and mask thingy
                ExtensionNode ext{
                    nibbles64{
                        1, {non_empty_nib}}};
                cast_line(parent, ext);
            }

            // ext -> ext = ext
            if (grid_line.kind == kExt && parent.kind == kExt) {
                parent.ext.path.append(grid_line.ext.path);
                parent.ext.child = grid_line.ext.child;
                parent.ext.child_len = grid_line.ext.child_len;
                parent.child_depth[0] = 0;
                grid_.pop_back();
                return;
            }

            // ext -> leaf = leaf
            if (grid_line.kind == kLeaf && parent.kind == kExt) {
                auto parent_depth = grid_line.parent_depth;
                nibbles64 new_path{parent.ext.path};
                new_path.append(grid_line.leaf.path);
                grid_line.parent_depth = parent.parent_depth;
                grid_line.parent_slot = parent.parent_slot;
                grid_line.leaf.path = new_path;
                // grid_line.consumed = 0;       // Useful for deleted leafs on the way up
                // Copy the back element to parent position
                grid_[parent_depth] = grid_line;
                // Remove the back
                grid_.pop_back();  // remove the line whee the leaf used to be
                return;
            }
        }
    }

    auto node_ref = encode_line(grid_line);
    if (node_ref.size() >= 32) {
        node_ref = keccak_bytes(node_ref);
    }
    if (grid_.size() > 0) {
        auto& parent = grid_[grid_line.parent_depth];
        switch (parent.kind) {
            case kBranch:
                if (node_ref.size() == 1){
                    parent.branch.delete_child(grid_line.parent_slot);
                } else {
                    parent.branch.set_child(grid_line.parent_slot, node_ref);
                }
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
        grid_.emplace_back(kLeaf, parent_slot, parent_depth, 0);
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
        auto& parent = grid_[parent_depth];
        grid_.back().consumed += parent.consumed;
        parent.child_depth[parent_slot] = depth_;
        if (parent.kind == kBranch && parent.branch.child_len[parent_slot] == 0) {
            parent.branch.count++;
            parent.branch.mask |= (1 << parent_slot);
            parent.branch.child_len[parent_slot] = 1;  // Placeholder, update during fold_back
        }
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
        if (line.ext.path.len > parent_consumed) {
            sys_println(("ERROR: [fold_unfold.cpp:203] consumed underflow in cast_line! parent_consumed=" +
                         std::to_string(parent_consumed) + " line.ext.path.len=" + std::to_string(line.ext.path.len))
                            .c_str());
        }
        parent_consumed = parent_consumed - line.ext.path.len;
    } else if (line.kind == kBranch) {
        if (parent_consumed < 1) {
            sys_println(("ERROR: [fold_unfold.cpp:205] consumed underflow in cast_line! parent_consumed=" +
                         std::to_string(parent_consumed) + " (branch consumes 1)")
                            .c_str());
        }
        parent_consumed = parent_consumed - 1;
    } else {  // leaf
        // if (line.leaf.path.len > parent_consumed) {
        //     sys_println(("ERROR: [fold_unfold.cpp:207] consumed underflow in cast_line! parent_consumed=" +
        //                 std::to_string(parent_consumed) + " line.leaf.path.len=" + std::to_string(static_cast<int>(line.leaf.path.len))).c_str());
        // }
        // parent_consumed = parent_consumed - line.leaf.path.len;
    }
    line.child_depth.fill(0);

    Kind kind;
    uint8_t consumed;
    if constexpr (std::is_same_v<NodeType, LeafNode>) {
        kind = kLeaf;
        consumed = 0;
        line.leaf = node;
    } else if constexpr (std::is_same_v<NodeType, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;
        line.ext = node;
        // std::memcpy(std::addressof(line.ext), &node, sizeof(node));
        if (consumed + parent_consumed > 255) {
            sys_println(("ERROR: [fold_unfold.cpp:223] consumed overflow in cast_line! consumed=" +
                         std::to_string(consumed) + " parent_consumed=" + std::to_string(parent_consumed))
                            .c_str());
        }
        line.child_depth.fill(0);
    } else {
        kind = kBranch;
        consumed = 1;
        line.branch = node;
        // std::memcpy(std::addressof(line.branch), &node, sizeof(node));
        if (consumed + parent_consumed > 255) {
            sys_println(("ERROR: [fold_unfold.cpp:230] consumed overflow in cast_line! consumed=" +
                         std::to_string(consumed) + " parent_consumed=" + std::to_string(parent_consumed))
                            .c_str());
        }
    }
    line.consumed = consumed + parent_consumed;
    line.kind = kind;
    return true;
}

template <bool DeletionEnabled>
uint8_t GridMPT<DeletionEnabled>::consumed_nibbles(GridLine& line) {
    if (grid_.size() > 0) {
        auto parent_consumed = grid_[line.parent_depth].consumed;
        if (line.consumed < parent_consumed) {
            sys_println(("ERROR: [fold_unfold.cpp:239] consumed underflow in consumed_nibbles! line.consumed=" +
                         std::to_string(line.consumed) + " parent_consumed=" + std::to_string(parent_consumed) +
                         " line.parent_depth=" + std::to_string(line.parent_depth))
                            .c_str());
        }
        return line.consumed - parent_consumed;
    } else {
        return line.consumed;
    }
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
    // constexpr auto DEBUG_CHILD = 0xd56a543f689dd0750b90d9420e058a6491882d80f189692f2c74146e30449ab4_bytes32;
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
    // if (child == DEBUG_CHILD){
    //     sys_println("Found the DEBUG_CHILD");
    //     sys_println(grid_[depth_].to_string().c_str());
    // }
    return success;
}

// Fold children folds all the children of the line at given depth
template <bool DeletionEnabled>
inline void GridMPT<DeletionEnabled>::fold_children(uint8_t parent_depth) {
    while (grid_.size() - 1 > parent_depth) fold_back();
}

}  // namespace silkworm::mpt
