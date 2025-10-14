// #pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <evmone_precompiles/keccak.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/encode.hpp>

#include "helpers.hpp"
#include "mpt.hpp"

// using namespace evmc;
namespace silkworm::mpt {

// Hex-Prefix encode-decode functions

inline size_t hp_size(size_t nibbles) { return 1 + ((nibbles + 1) >> 1); }

inline uint8_t* encode_hp_path(uint8_t* p, const uint8_t* nib, size_t n, bool leaf) {
    const bool odd = (n & 1);
    const uint8_t flag = (leaf ? 0x2 : 0x0) | (odd ? 0x1 : 0x0);
    *p++ = static_cast<uint8_t>((flag << 4) | (odd ? (n ? (nib[0] & 0x0F) : 0) : 0));
    size_t i = odd ? 1 : 0;
    for (; i + 1 < n; i += 2) *p++ = static_cast<uint8_t>((nib[i] << 4) | (nib[i + 1] & 0x0F));
    if (i < n) *p++ = static_cast<uint8_t>((nib[i] << 4));  // last high nibble only
    return p;
}

// HP decode → (is_leaf, nibbles[]). Returns false on malformed.
inline bool hp_decode(ByteView in, bool& is_leaf, std::array<uint8_t, 64>& out, uint8_t& out_len) {
    if (in.empty()) return false;
    uint8_t flag = in[0] >> 4;
    is_leaf = (flag & 0x2) != 0;
    const bool odd = (flag & 0x1) != 0;
    uint8_t nib0 = in[0] & 0x0F;

    size_t pos = 1;
    out_len = 0;

    if (odd) {
        out[out_len++] = nib0 & 0x0F;
    }
    for (; pos < in.size(); ++pos) {
        out[out_len++] = (in[pos] >> 4) & 0x0F;
        out[out_len++] = in[pos] & 0x0F;
        if (out_len > 64) return false;
    }
    return true;
}
// --------------

// ---------------------------------------------
// Encoding from Grid lines (folding)
// ---------------------------------------------

inline Bytes encode_branch(const BranchNode& b) {
    // Size inner items
    size_t inner = 0;
    for (int i = 0; i < 16; ++i) inner += rlp_size_str(is_zero(b.child[i]) ? 0 : 32, /*literal*/ false);
    inner += rlp_size_str(b.value.size(), /*literal*/ true, b.value.size() ? b.value[0] : 0x00);
    // Out buf
    Bytes out;
    out.resize(rlp_size_list(inner));
    uint8_t* p = reinterpret_cast<uint8_t*>(out.data());
    p = rlp_put_list_hdr(p, inner);
    // 16 children
    for (int i = 0; i < 16; ++i) {
        if (is_zero(b.child[i])) {
            *p++ = 0x80;
        } else
            p = rlp_put_str(p, b.child[i].bytes, 32, /*literal*/ false);
    }
    // value
    if (b.value.size() == 0) {
        *p++ = 0x80;
    } else
        p = rlp_put_str(p, b.value.data(), b.value.size(), /*literal*/ true, b.value[0]);
    return out;
}

inline Bytes encode_ext(const ExtensionNode& e) {
    const size_t hp_sz = hp_size(e.path.len);
    const size_t s0 = rlp_size_str(hp_sz, false);
    const size_t s1 = rlp_size_str(32, false);
    const size_t inner = s0 + s1;
    Bytes out;
    out.resize(rlp_size_list(inner));
    uint8_t* p = reinterpret_cast<uint8_t*>(out.data());
    p = rlp_put_list_hdr(p, inner);
    // item0
    {
        // Write the HP-encoded path to a tiny temp
        uint8_t hpbuf[1 + 32];  // 65 max
        uint8_t* q = encode_hp_path(hpbuf, e.path.nib.data(), e.path.len, /*leaf*/ false);
        p = rlp_put_str(p, hpbuf, size_t(q - hpbuf), false);
    }
    // item1
    p = rlp_put_str(p, e.child.bytes, 32, false);
    return out;
}

inline Bytes encode_leaf(const LeafNode& l) {
    const size_t hp_sz = hp_size(l.path.len);
    const size_t s0 = rlp_size_str(hp_sz, false);
    const size_t s1 = rlp_size_str(l.value.size(), true, l.value.size() ? l.value[0] : 0);
    const size_t inner = s0 + s1;
    Bytes out;
    out.resize(rlp_size_list(inner));
    uint8_t* p = reinterpret_cast<uint8_t*>(out.data());
    p = rlp_put_list_hdr(p, inner);
    // item0
    {
        uint8_t hpbuf[1 + 32];
        uint8_t* q = encode_hp_path(hpbuf, l.path.nib.data(), l.path.len, /*leaf*/ true);
        p = rlp_put_str(p, hpbuf, size_t(q - hpbuf), false);
    }
    // item1
    if (l.value.size() == 0)
        *p++ = 0x80;
    else
        p = rlp_put_str(p, l.value.data(), l.value.size(), true, l.value[0]);
    return out;
}

inline evmc::bytes32 keccak_bytes(const Bytes& x) {
    return std::bit_cast<evmc_bytes32>(ethash_keccak256(reinterpret_cast<const uint8_t*>(x.data()), x.size()));
}

// ---------------------------------------------
// Update mechanics (modify/insert with splits)
// ---------------------------------------------

// Create a leaf for remaining key suffix (after consuming one child nibble already if needed)
inline bytes32 make_leaf_for_suffix(const uint8_t* suffix, uint8_t len, ByteView value,
                                    const NodeStore& store) {
    LeafNode l{};
    l.path.len = len;
    if (len) std::memcpy(l.path.nib.data(), suffix, len);
    l.value = value;
    Bytes enc = encode_leaf(l);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

// Make a branch with two children per a split: old (from existing child), new (from key suffix)
inline bytes32 make_branch_two_children(uint8_t old_idx, const bytes32& old_child_hash,
                                        uint8_t new_idx, const uint8_t* new_suffix, uint8_t new_len,
                                        ByteView new_value, const NodeStore& store) {
    BranchNode b{};
    // Old side: place existing subtree under old_idx
    b.child[old_idx] = old_child_hash;
    b.mask |= static_cast<uint16_t>(1u << old_idx);
    b.count++;
    // New side: create a new leaf for new suffix (after consuming new_idx)
    bytes32 new_leaf = make_leaf_for_suffix(new_suffix, new_len, new_value, store);
    b.child[new_idx] = new_leaf;
    b.mask |= static_cast<uint16_t>(1u << new_idx);
    b.count++;
    // Encode & hash
    Bytes enc = encode_branch(b);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

// Wrap a child under a single-nibble Extension prefix (path one nibble)
inline bytes32 wrap_ext_1(uint8_t nib, const bytes32& child, const NodeStore& store) {
    ExtensionNode e{};
    e.path.len = 1;
    e.path.nib[0] = nib;
    e.child = child;
    Bytes enc = encode_ext(e);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

// Build an Extension over a Branch for a common prefix of length m>=1
inline bytes32 wrap_ext_multi(const uint8_t* common, uint8_t m, const bytes32& child,
                              const NodeStore& store) {
    ExtensionNode e{};
    e.path.len = m;
    std::memcpy(e.path.nib.data(), common, m);
    e.child = child;
    Bytes enc = encode_ext(e);
    bytes32 h = keccak_bytes(enc);
    if (store.put_rlp) store.put_rlp(h, enc);
    return h;
}

struct AccTrieNode {
    bytes32 key;
    ByteView value_rlp;
};

// Unfold from root as we traverse through the list of account updates
// Finally return the root
inline bytes32 calc_trie_grid(bytes32 prev_root,
                              const NodeStore& store,
                              const std::vector<AccTrieNode>& updates_sorted) {
    // The max-depth of the trie can be 64.
    std::array<GridLine, 64> grid{};

    uint8_t depth = 0;
    bytes32 cur = prev_root;  // The hash at current line
    auto updates_it = updates_sorted.begin();
    bool hasCommon = true;
    bool should_unfold = updates_it < updates_sorted.end() && hasCommon;
    bool is_searching = false;
    bool should_fold = false;
    uint8_t fold_for = 0;
    Nibbles64 current_nibbles;
    Nibbles64 previous_nibbles;
    uint8_t curr_nib_i;

    // Load root on to first line
    unfold_node_from_hash(store, cur, grid[depth++], current_nibbles.nib[curr_nib_i]);
    do {
        // At the start of the loop the grid_line is invariably going to be a branch node
        GridLine& grid_line = grid[depth];  // Point to this line with ref

        // First do the pending folds
        if (should_fold) {
            should_fold = false;
            // hash the current line
            bytes32 h;
            switch (grid_line.kind) {
                case kBranch:
                    h = keccak_bytes(encode_branch(grid_line.branch));
                    break;
                case kExt:
                    h = keccak_bytes(encode_ext(grid_line.ext));
                    break;
                case kLeaf:
                    h = keccak_bytes(encode_leaf(grid_line.leaf));
                    break;
                default:
                    break;
            }
            depth--;
            if (depth > 0) {
                auto& parent = grid[depth];
                switch (parent.kind) {
                    case kBranch:
                        parent.branch.child[parent.cur_slot] = h;
                        break;
                    case kExt:
                        parent.ext.child = h;
                        break;
                    default:
                        break;
                }
            } else {    // stop folding after root
                cur = h;
                break;
            }
            if (fold_for > 0) {
                should_fold = true;
                fold_for--;
                continue;
            }
        }
        if (should_unfold) {
            unfold_node_from_hash(store, cur, grid_line, current_nibbles.nib[curr_nib_i]);
            should_unfold = false;
            depth++;  // next depth
        }

        // If there is no current item being searched for upwards or downwards
        if (!is_searching && updates_it < updates_sorted.end()) {
            auto new_nibbles = Nibbles64::from_bytes32(updates_it->key);
            auto lcp = 0;
            if (current_nibbles.len > 0) {
                while (new_nibbles.nib[lcp] == current_nibbles.nib[lcp]) lcp++;
                fold_for = curr_nib_i - lcp;
                if (fold_for > 0) {
                    should_fold = true;
                }
                curr_nib_i = lcp;
            } else {
                // should_unfold
            }
            is_searching = true;
            current_nibbles = new_nibbles;
            updates_it++;  // For the next lookup
            continue;
        }

        // Searching down
        if (is_searching) {
            if (grid_line.kind == kBranch) {
                grid_line.cur_slot = current_nibbles.nib[curr_nib_i];
                auto& h_at_branch_slot = grid_line.branch.child[grid_line.cur_slot];
                if (is_zero(h_at_branch_slot)) {
                    // insert
                    bytes32 leaf_h = make_leaf_for_suffix(
                        &current_nibbles.nib[curr_nib_i + 1],
                        64 - (curr_nib_i + 1),
                        updates_it->value_rlp,
                        store);
                    grid_line.branch.child[grid_line.cur_slot] = leaf_h;
                } else {
                    should_unfold = true;  // further unfold
                    cur = h_at_branch_slot;
                    curr_nib_i++;
                    continue;
                }
            } else if (grid_line.kind == kExt) {
                // go down till the first divergence point
                uint8_t m = 0;
                while (m < grid_line.ext.path.len && (curr_nib_i + m) < 64 && grid_line.ext.path.nib[m] == current_nibbles.nib[curr_nib_i + m]) ++m;
                grid_line.consumed = m;  // probably not needed
                curr_nib_i += m;

                if (m == grid_line.ext.path.len) {
                    // Full match → continue below
                    cur = grid_line.ext.child;
                    should_unfold = true;
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
                        grid_line = grid[depth++];
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

                    bn.count = 2;
                    bn.child[current_nibbles.nib[curr_nib_i]] = make_leaf_for_suffix(
                        &current_nibbles.nib[curr_nib_i + 1],
                        64 - (curr_nib_i + 1),
                        updates_it->value_rlp,
                        store);
                    std::memcpy(std::addressof(grid_line.branch), &bn, sizeof(BranchNode));
                    grid_line.kind = kBranch;
                    grid_line.cur_slot = current_nibbles.nib[curr_nib_i];
                    // insertion complete
                    is_searching = false;
                    should_unfold = false;
                    continue;
                }
            } else {  // it's a leaf
                BranchNode bn{};
                // Find common path and create extension and push - unfolding, depth++ after
                auto i = 0;
                while (grid_line.leaf.path.nib[i] == current_nibbles.nib[curr_nib_i + i]) ++i;
                if (curr_nib_i + i == 64){
                    // This path exists in the tree already, it's an update and not insert, skip creating a new branch node
                    grid_line.leaf.value = updates_it->value_rlp;
                    auto h = keccak_bytes(encode_leaf(grid_line.leaf));
                    is_searching = false;
                    should_unfold = false;
                    should_fold = true;
                    continue;
                }else if (i > 0) {
                    Nibbles64 common_path{};
                    std::memcpy(common_path.nib.data(), grid_line.leaf.path.nib.data(), i);
                    common_path.len = i;
                    ExtensionNode ext_common{};
                    ext_common.path = common_path;
                    ext_common.child = bytes32{};  // update later
                    curr_nib_i += i;

                    // Have to re-hash the old leaf
                    bn.child[grid_line.leaf.path.nib[i]] = make_leaf_for_suffix(
                        &grid_line.leaf.path.nib[grid_line.leaf.path.nib[i] + 1],
                        64 - (grid_line.leaf.path.nib[i] + 1),
                        grid_line.leaf.value,
                        store);
                } else {
                    // re-use the hash
                    bn.child[grid_line.leaf.path.nib[i]] = cur;
                }
                bn.child[current_nibbles.nib[curr_nib_i]] = make_leaf_for_suffix(
                    &current_nibbles.nib[curr_nib_i + 1],
                    64 - (curr_nib_i + 1),
                    updates_it->value_rlp,
                    store);

                std::memcpy(std::addressof(grid_line.branch), &bn, sizeof(BranchNode));
                grid_line.kind = kBranch;
                grid_line.cur_slot = current_nibbles.nib[curr_nib_i];
                // insertion complete
                is_searching = false;
                should_unfold = false;
                continue;
            }
        } else {
            should_fold = true;  // keep folding till root
        }
    } while (should_unfold || should_fold || depth > 0);

    return cur;
}

}  // namespace silkworm::mpt
