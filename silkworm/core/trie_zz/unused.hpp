#pragma once
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

#include "mpt.hpp"
#include "helpers.hpp"

// namespace silkworm::mpt {

// // Wrap a child under a single-nibble Extension prefix (path one nibble)
// inline bytes32 wrap_ext_1(uint8_t nib, const bytes32& child, const NodeStore& store) {
//     ExtensionNode e{};
//     e.path.len = 1;
//     e.path.nib[0] = nib;
//     e.child = child;
//     Bytes enc = encode_ext(e);
//     bytes32 h = keccak_bytes(enc);
//     if (store.put_rlp) store.put_rlp(h, enc);
//     return h;
// }

// // Build an Extension over a Branch for a common prefix of length m>=1
// inline bytes32 wrap_ext_multi(const uint8_t* common, uint8_t m, const bytes32& child,
//                               const NodeStore& store) {
//     ExtensionNode e{};
//     e.path.len = m;
//     std::memcpy(e.path.nib.data(), common, m);
//     e.child = child;
//     Bytes enc = encode_ext(e);
//     bytes32 h = keccak_bytes(enc);
//     if (store.put_rlp) store.put_rlp(h, enc);
//     return h;
// }


// inline bool decode_branch(ByteView payload, BranchNode& br) {
//     // Expect exactly 17 RLP strings concatenated inside payload.
//     RlpReader it{payload};
//     for (int idx = 0; idx < 16; ++idx) {
//         auto s = it.read_string();
//         if (!s) return false;
//         if (s->size() == 0) {
//             zero(br.child[idx]);
//         } else {
//             if (s->size() != 32) return false;
//             std::memcpy(br.child[idx].bytes, s->data(), 32);
//             br.mask |= static_cast<uint16_t>(1u << idx);
//             ++br.count;
//         }
//     }
//     auto val = it.read_string();
//     if (!val) return false;
//     br.value = {val->data(), val->size()};
//     return it.eof();
// }

// inline bool decode_ext_or_leaf(ByteView payload, bool& is_leaf,
//                                std::array<uint8_t, 64>& path_out, uint8_t& path_len_out,
//                                ByteView& second) {
//     RlpReader it{payload};
//     auto p0 = it.read_string();
//     if (!p0) return false;
//     if (!hp_decode(*p0, is_leaf, path_out, path_len_out)) return false;
//     auto p1 = it.read_string();
//     if (!p1) return false;
//     second = *p1;
//     return it.eof();
// }


// // Make a branch with two children per a split: old (from existing child), new (from key suffix)
// inline bytes32 make_branch_two_children(uint8_t old_idx, const bytes32& old_child_hash,
//                                         uint8_t new_idx, const uint8_t* new_suffix, uint8_t new_len,
//                                         ByteView new_value, const NodeStore& store) {
//     BranchNode b{};
//     // Old side: place existing subtree under old_idx
//     b.child[old_idx] = old_child_hash;
//     b.mask |= static_cast<uint16_t>(1u << old_idx);
//     b.count++;
//     // New side: create a new leaf for new suffix (after consuming new_idx)
//     bytes32 new_leaf = make_leaf_for_suffix(new_suffix, new_len, new_value, store);
//     b.child[new_idx] = new_leaf;
//     b.mask |= static_cast<uint16_t>(1u << new_idx);
//     b.count++;
//     // Encode & hash
//     Bytes enc = encode_branch(b);
//     bytes32 h = keccak_bytes(enc);
//     if (store.put_rlp) store.put_rlp(h, enc);
//     return h;
// }
// }  // namespace silkworm::mpt
