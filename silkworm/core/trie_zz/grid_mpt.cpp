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

#include "fold_unfold.cpp"
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
// Find the least common path of current key from the top, with the last key as reference
template <bool DeletionEnabled>
inline void GridMPT<DeletionEnabled>::seek_with_last_insert(nibbles64& new_nibbles) {
    //================================================
    // The last leaf must have been inserted to a branch, or (to be) deleted from it
    // 3 cases:
    // 1. If parent_consumed - 1 < lcp, the new leaf shares path, have to split
    // 2. if lcp == parent_consumed - 1, we are at common parent branch
    // 3. if lcp < parent_consumed - 1, fold the children and possibly more
    //
    // Tip: When we are searching for the next nibble, we don't need more than
    // the first level of children from the common branch, ever again
    //================================================
    if (grid_.size() == 1) return;
    size_t lcp = 0;
    auto& last_insert = grid_.back();
    auto cur_parent_depth = last_insert.parent_depth;
    auto parent_consumed = grid_[cur_parent_depth].consumed;

    if (grid_[last_insert.parent_depth].kind != kBranch) {
        sys_println("ERROR: seek_with_last_insert parent not a branch");
        depth_ = 0;
        return;
    }
    while (new_nibbles[lcp] == search_nibbles_[lcp] && lcp < parent_consumed) ++lcp;

    if (lcp >= parent_consumed) {
        if constexpr (DeletionEnabled) {
            if (last_insert.leaf.marked_for_deletion) {
                search_nib_cursor_ = search_nib_cursor_ - 1;  // start from the parent branch
                depth_ = cur_parent_depth;
                fold_back();
                return;
            }
        }
    } else if (cur_parent_depth > 0) {
        auto next_parent_depth = grid_[cur_parent_depth].parent_depth;
        parent_consumed = grid_[next_parent_depth].consumed;    // For the next parent
        while (parent_consumed > lcp && cur_parent_depth > 0) {
            fold_children(cur_parent_depth);
            cur_parent_depth = next_parent_depth;
            next_parent_depth = grid_[cur_parent_depth].parent_depth;
            parent_consumed = grid_[next_parent_depth].consumed;
        }
        depth_ = cur_parent_depth;
    } else {
        depth_ = cur_parent_depth;
    }

    if (depth_ == 0) {
        search_nib_cursor_ = 0;
    } else {
        search_nib_cursor_ = parent_consumed;
    }
    if (search_nib_cursor_ > 63) {
        sys_println("ERROR: search_nib_cursor_ > 63)");
    }
   
}

// Unfold from root as we traverse through the list of account updates
// Finally return the root
template <bool DeletionEnabled>
bytes32 GridMPT<DeletionEnabled>::calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted) {
    // Reset state for fresh calculation
    grid_.clear();
    depth_ = 0;
    search_nib_cursor_ = 0;
    search_nibbles_ = nibbles64{};

    if (prev_root_ != kEmptyRoot) {
        // Load root on to first line
        auto rlp = node_store_.get_rlp(prev_root_);
        unfold_node_from_rlp(rlp, 0, 0);
        // sys_println(grid_to_string().c_str());
    }

    for (const auto& trie_upd : updates_sorted) {
        const ByteView value_view{trie_upd.value_rlp};

        // ==============DEBUG===========
        sys_println(("\n Key: " + to_hex(trie_upd.key.bytes)).c_str());
        constexpr auto debg_key = 0x6a389f876f6d51e458c0ad85e4bf8b99377260c4a6fbe049fe2211bfc5af42c7_bytes32;
        if (trie_upd.key == debg_key) {
            sys_println("Found update key");
            // sys_println(grid_[7].to_string().c_str());
            // sys_println(grid_[grid_[0].child_depth[6]].to_string().c_str());
        }
        // =========================

        auto new_nibbles = nibbles64::from_bytes32(trie_upd.key);
        search_nib_cursor_ = 0;

        // Handle empty grid case before accessing grid_[depth_]
        if (grid_.empty()) {
            search_nibbles_ = new_nibbles;
            LeafNode l{search_nibbles_, 0, value_view};
            insert_line(0, 0, l);
            continue;
        }
        if (search_nibbles_.len > 0) {
            // Previous leaf exists, and it's in a branch (can't be ext)
            seek_with_last_insert(new_nibbles);
        }
        search_nibbles_ = new_nibbles;
        // auto grid_counter = 1;
        while (depth_ < 64) {  // Searching down
            auto& grid_line = grid_[depth_];
            if (grid_line.kind == kBranch) {
                auto nib = search_nibbles_[search_nib_cursor_];
                if (!unfold_slot(nib)) {
                    // Child is empty - insert here
                    auto l = make_cur_leaf(value_view);
                    insert_line(l.parent_slot, depth_, l);
                    break;
                }
                search_nib_cursor_++;
                continue;
            } else if (grid_line.kind == kExt) {
                // go down till the first divergence point
                uint8_t m = 0;
                while (m < grid_line.ext.path.len && (search_nib_cursor_ + m) < 64 && grid_line.ext.path[m] == search_nibbles_[search_nib_cursor_ + m]) ++m;
                search_nib_cursor_ += m;

                if (m == grid_line.ext.path.len) {
                    // Full match -> unfold child
                    ByteView rlp;
                    if (grid_line.ext.child_len < 32) {
                        rlp = ByteView{grid_line.ext.child.bytes, grid_line.ext.child_len};
                    } else {
                        rlp = node_store_.get_rlp(grid_line.ext.child);
                    }

                    // Debug
                    std::cout << "  About to unfold from RLP with parent_slot=" << static_cast<int>(search_nibbles_[search_nib_cursor_])
                              << " (search_nib_cursor_=" << static_cast<int>(search_nib_cursor_) << ")" << std::endl;

                    unfold_node_from_rlp(rlp, 0, depth_);
                    continue;
                } else {
                    // We will now insert branch at the divergence point
                    // Note: m is at the point of divergence
                    BranchNode bn{};    // Zero-initialize
                    bn = BranchNode{};  // Ensure all fields are cleared
                    auto old_ext{grid_line.ext};
                    auto ext_path_len = old_ext.path.len;

                    if (m > 0) {
                        // Shorten the grid_line current extension till the divergence point
                        auto subtract_amount = ext_path_len - m;
                        if (subtract_amount > grid_line.consumed) {
                            sys_println(("ERROR: [grid_mpt.cpp:190] consumed underflow! grid_line.consumed=" + 
                                        std::to_string(grid_line.consumed) + 
                                        " subtract_amount=" + std::to_string(subtract_amount) + 
                                        " (ext_path_len=" + std::to_string(ext_path_len) + ", m=" + std::to_string(m) + ")").c_str());
                        }
                        grid_line.consumed = grid_line.consumed - subtract_amount;
                        grid_line.ext.path.len = m;
                        grid_line.ext.child = bytes32{};  // Update later with the created branch
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
                        // if (old_ext.path[m] < search_nibbles_[search_nib_cursor_]) {
                        //     fold_or_seek(depth_);  // Don't need to deal with left side nibbles in next iterations
                        // } else {
                        depth_ = d;  // set it to the branch
                        // }
                    } else {
                        // The extension is absorbed or not needed, so put the child directly into the newly created bn
                        grid_[depth_].branch.set_child(old_ext.path[m], ByteView{old_ext.child.bytes, old_ext.child_len});
                    }
                    auto l = make_cur_leaf(value_view);
                    insert_line(l.parent_slot, depth_, l);

                    break;  // insertion complete
                }
            } else {
                // It's a leaf:
                // Find common path and create extension and push
                // Note: grid_line.leaf.path.len == (64 - search_nib_cursor_)

                size_t cp = 0;
                while (grid_line.leaf.path[cp] == search_nibbles_[search_nib_cursor_ + cp] && cp < grid_line.leaf.path.len) ++cp;
                if (search_nib_cursor_ + cp == 64) {  // This path exists, update the value
                    if constexpr (DeletionEnabled) {
                        if (value_view == ByteView{{0x80}}) {
                            grid_line.leaf.marked_for_deletion = true;
                            break;
                        }
                    }
                    grid_line.leaf.value = value_view;
                    break;  // update complete
                }

                // Cache the value before splitting
                LeafNode old_leaf{grid_[depth_].leaf};
                BranchNode bn{};    // Zero-initialize
                bn = BranchNode{};  // Ensure all fields are cleared

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
                auto l = make_cur_leaf(value_view);          // sets parent_slot too at l, with first nib
                if (old_leaf.parent_slot > l.parent_slot) {  // ordering
                    insert_line(old_leaf.parent_slot, depth_, old_leaf);
                    insert_line(l.parent_slot, depth_ - 1, l);
                } else {
                    insert_line(l.parent_slot, depth_, l);
                    insert_line(old_leaf.parent_slot, depth_ - 1, old_leaf);
                    // fold_or_seek();
                }
                depth_ = grid_.size() - 1;  // set to inserted leaf
                break;                      // insertion complete
            }
        }
    }

    // Fold till root
    while (grid_.size() > 1) {
        fold_back();
    }
    auto encoded = encode_line(grid_[0]);
    // std::cout << "calc_root encoded branch: " << silkworm::to_hex(encoded) << std::endl;
    return keccak_bytes(encoded);
}

// Explicit template instantiations
template class GridMPT<false>;
template class GridMPT<true>;

}  // namespace silkworm::mpt
