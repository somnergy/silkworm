#pragma once
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
#include "rlp.hpp"

namespace silkworm::mpt {

// Decode node from hash into a GridLine and push onto grid
bool GridMPT::unfold_node_from_hash(const bytes32& hash, uint8_t parent_slot_index) {
    auto& grid_line = grid_[depth_];
    ByteView rlp = node_store_.get_rlp(hash);
    grid_line.hash = hash;
    grid_line.cur_slot = parent_slot_index;
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
            grid_line.kind = kBranch;
            std::memcpy(&grid_line.branch, &tmp, sizeof(tmp));  // POD copy
            grid_line.consumed = 1;
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
    if (depth_ > 0) {
        grid_line.consumed += grid_[depth_ - 1].consumed;
    }
    return true;
}

inline bool GridMPT::fold_nibbles(int nib_count) {
    while (nib_count > 0) {
        auto consumed_here = grid_[depth_].consumed;
        if (depth_ > 0) {
            consumed_here -= grid_[depth_ - 1].consumed;
        }
        nib_count -= consumed_here;
        if (!fold_lines(1)){
            return false;
        }
    }
    return true;
}

inline bool GridMPT::fold_lines(uint8_t num_lines) {
    while (num_lines) {
        GridLine& grid_line = grid_[depth_];
        hash_line(grid_line);
        if (depth_ > 0) {
            --depth_;
            auto& parent = grid_[depth_];
            switch (parent.kind) {
                case kBranch:
                    parent.branch.child[parent.cur_slot] = grid_line.hash;
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
// Encode and hash the given line and store it
void hash_line(GridLine& line) {
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

// Inserts leaf at current line's branch slot. The hash is calculated
inline bool GridMPT::insert_leaf(uint8_t slot, ByteView value_rlp) {
    if (depth_ >= 64) {
        return false;
    }
    GridLine& grid_line = grid_[depth_];
    if (grid_line.kind == kBranch) {
        bytes32 leaf_h = make_leaf_for_suffix(
            &search_nibbles_.nib[search_nib_cursor_ + 1],
            64 - (search_nib_cursor_ + 1),
            value_rlp,
            node_store_);
        grid_line.branch.child[slot] = leaf_h;
        return true;
    }
    return false;
}

// Inserts extension at current depth_
inline bool GridMPT::insert_extension(ExtensionNode& ext){
    if (depth_ >= 64) {
        return false;
    }
    GridLine& grid_line = grid_[depth_];
    std::memcpy(std::addressof(grid_line.ext), &ext, sizeof(ExtensionNode));
    grid_line.kind = kExt;
    return true;
}

// Inserts branch at current depth_
inline bool GridMPT::insert_branch(BranchNode& bn, uint8_t slot) {
    if (depth_ >= 64) {
        return false;
    }
    GridLine& grid_line = grid_[depth_];
    std::memcpy(std::addressof(grid_line.branch), &bn, sizeof(BranchNode));
    grid_line.kind = kBranch;
    grid_line.cur_slot = slot;
    return true;
}
// Unfold from root as we traverse through the list of account updates
// Finally return the root
inline bytes32 GridMPT::calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted) {
    // Load root on to first line
    unfold_node_from_hash(prev_root, 0);

    for (auto trie_upd : updates_sorted) {
        auto new_nibbles = nibbles64::from_bytes32(trie_upd.key);

        // Find the least common path with the last inserted nibbles as reference
        auto lcp = 0;  // store lowest common prefix with this line (a branch)
        while (new_nibbles.nib[lcp] == search_nibbles_.nib[lcp] && lcp < grid_[depth_].consumed) lcp++;
        auto fold_for = grid_[depth_].consumed - lcp - 1;

        // Fold to reach lcp point in grid - never have to visit that again
        if (fold_for > 0 && !fold_nibbles(fold_for)) {
            return bytes32{};
        }
        search_nib_cursor_ = lcp;
        search_nibbles_ = new_nibbles;

        // Searching down
        while (depth_ < 64) {
            auto& grid_line = grid_[depth_];
            if (grid_line.kind == kBranch) {
                grid_line.cur_slot = search_nibbles_.nib[search_nib_cursor_];
                auto& h_at_branch_slot = grid_line.branch.child[grid_line.cur_slot];
                if (is_zero(h_at_branch_slot)) {
                    // insert
                    insert_leaf(grid_line.cur_slot, trie_upd.value_rlp);
                    break;
                } else {
                    ++depth_;
                    unfold_node_from_hash(h_at_branch_slot, search_nibbles_.nib[search_nib_cursor_]);
                    search_nib_cursor_++;
                    continue;
                }
            } else if (grid_line.kind == kExt) {
                // go down till the first divergence point
                uint8_t m = 0;
                while (m < grid_line.ext.path.len && (search_nib_cursor_ + m) < 64 && grid_line.ext.path.nib[m] == search_nibbles_.nib[search_nib_cursor_ + m]) ++m;
                search_nib_cursor_ += m;

                if (m == grid_line.ext.path.len) {
                    // Full match -> continue below
                    ++depth_;
                    unfold_node_from_hash(grid_line.ext.child, search_nibbles_.nib[search_nib_cursor_]);
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

                        // Keep this line with extension and add a new line to the grid
                        ++depth_;
                        grid_line = grid_[depth_];
                    }

                    ext_path_len -= m;

                    if (ext_path_len > 0) {
                        // Insert an extension node for the remainder of extension after the branch
                        ExtensionNode ext_mplus1{};
                        ext_mplus1.path.len = ext_path_len;
                        std::memcpy(ext_mplus1.path.nib.data(),
                                    old_ext.path.nib.data() + m,
                                    ext_mplus1.path.len);
                        ext_mplus1.child = old_ext.child;
                        bn.child[old_ext.path.nib[m]] = keccak_bytes(encode_ext(ext_mplus1));
                    } else {
                        // The extension is absorbed or not needed, so put the child directly into the newly created bn
                        bn.child[old_ext.path.nib[m]] = old_ext.child;
                    }
                    bn.count = 2;  // at this point
                    insert_branch(bn, search_nibbles_.nib[search_nib_cursor_]);
                    insert_leaf(grid_line.cur_slot, trie_upd.value_rlp);
                    break;  // insertion complete
                }
            } else {  // it's a leaf
                BranchNode bn{};
                // Find common path and create extension and push - unfolding, depth_++ after
                auto i = 0;
                while (grid_line.leaf.path.nib[i] == search_nibbles_.nib[search_nib_cursor_ + i]) ++i;
                if (search_nib_cursor_ + i == 64) {
                    // This path exists in the tree already, update the value and fold
                    grid_line.leaf.value = trie_upd.value_rlp;
                    if (!fold_lines(1)) {
                        return bytes32{};
                    }
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
                    bn.child[grid_line.leaf.path.nib[i]] = make_leaf_for_suffix(
                        &grid_line.leaf.path.nib[i+1],
                        grid_line.leaf.path.len-(i+1),
                        grid_line.leaf.value,
                        node_store_);
                    insert_extension(ext_common);
                    ++depth_;
                } else {
                    // re-use the hash
                    bn.child[grid_line.leaf.path.nib[i]] = grid_line.hash;
                }
                insert_branch(bn, search_nibbles_.nib[search_nib_cursor_]);
                insert_leaf(grid_line.cur_slot, trie_upd.value_rlp);
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
