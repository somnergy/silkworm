// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <map>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie_zz/helpers.hpp>
#include <silkworm/core/trie_zz/mpt.hpp>
#include <silkworm/core/trie_zz/rlp_sw.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include "../mpt.hpp"

namespace silkworm::mpt {

// =============================================================================
// Mock NodeStore for Testing
// =============================================================================

class MockNodeStore {
  public:
    std::map<bytes32, Bytes, std::less<>> storage_;

    NodeStore make_store() {
        NodeStore store;
        store.get_rlp = [this](const bytes32& hash) -> ByteView {
            auto it = storage_.find(hash);
            if (it == storage_.end()) {
                static Bytes empty;
                return ByteView{empty};
            }
            return ByteView{it->second};
        };
        store.put_rlp = [this](const bytes32& hash, const Bytes& rlp) {
            storage_[hash] = rlp;
        };
        return store;
    }

    void clear() { storage_.clear(); }

    size_t size() const { return storage_.size(); }
    
    // Helper to manually insert nodes for testing
    void insert(const bytes32& hash, const Bytes& rlp) {
        storage_[hash] = rlp;
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

bytes32 make_key(const std::string& hex) {
    bytes32 key{};
    auto bytes = from_hex(hex);
    std::memcpy(key.bytes, bytes->data(), std::min(size_t(32), bytes->size()));
    return key;
}

ByteView make_value(const std::string& str) {
    static std::vector<Bytes> values;
    // RLP-encode the value before storing it
    Bytes encoded;
    rlp::encode(encoded, ByteView{reinterpret_cast<const uint8_t*>(str.data()), str.size()});
    values.push_back(encoded);
    return ByteView{values.back()};
}

// Helper to build a simple trie manually
struct TrieBuilder {
    MockNodeStore& store;
    
    explicit TrieBuilder(MockNodeStore& s) : store(s) {}
    
    // Create a single leaf and return its hash
    bytes32 make_leaf(const std::string& hex_suffix, const std::string& value) {
        LeafNode leaf{};
        auto suffix_bytes = from_hex(hex_suffix);
        
        // Convert hex to nibbles
        leaf.path.len = 0;
        for (size_t i = 0; i < suffix_bytes->size() && leaf.path.len < 64; ++i) {
            leaf.path[leaf.path.len++] = (suffix_bytes->at(i) >> 4) & 0x0F;
            if (leaf.path.len < 64) {
                leaf.path[leaf.path.len++] = suffix_bytes->at(i) & 0x0F;
            }
        }
        
        leaf.value = make_value(value);
        
        Bytes encoded = encode_leaf(leaf);
        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }
    
    // Create a branch with specified children and return its hash
    bytes32 make_branch(const std::vector<std::pair<uint8_t, bytes32>>& children) {
        BranchNode branch{};
        std::memset(&branch, 0, sizeof(BranchNode));
        
        for (const auto& [idx, child_hash] : children) {
            branch.child[idx] = child_hash;
            branch.mask |= (1u << idx);
            branch.count++;
        }
        
        Bytes encoded = encode_branch(branch);
        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }
    
    // Create an extension and return its hash
    bytes32 make_extension(const std::string& hex_path, const bytes32& child_hash) {
        ExtensionNode ext{};
        auto path_bytes = from_hex(hex_path);
        
        // Convert hex to nibbles
        ext.path.len = 0;
        for (size_t i = 0; i < path_bytes->size() && ext.path.len < 64; ++i) {
            ext.path[ext.path.len++] = (path_bytes->at(i) >> 4) & 0x0F;
            if (ext.path.len < 64) {
                ext.path[ext.path.len++] = path_bytes->at(i) & 0x0F;
            }
        }
        
        ext.child = child_hash;
        
        Bytes encoded = encode_ext(ext);
        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }
};

// =============================================================================
// Basic Tests
// =============================================================================

TEST_CASE("nibbles64 operator[]") {
    SECTION("basic access") {
        nibbles64 n;
        n.len = 5;
        n[0] = 0x0F;
        n[1] = 0x0A;
        n[2] = 0x05;

        CHECK(n[0] == 0x0F);
        CHECK(n[1] == 0x0A);
        CHECK(n[2] == 0x05);
    }

    SECTION("from_bytes32") {
        bytes32 key{};
        key.bytes[0] = 0xAB;
        key.bytes[1] = 0xCD;

        auto nibbles = nibbles64::from_bytes32(key);

        CHECK(nibbles.len == 64);
        CHECK(nibbles[0] == 0x0A);  // High nibble of 0xAB
        CHECK(nibbles[1] == 0x0B);  // Low nibble of 0xAB
        CHECK(nibbles[2] == 0x0C);  // High nibble of 0xCD
        CHECK(nibbles[3] == 0x0D);  // Low nibble of 0xCD
    }
}

TEST_CASE("RLP encoding") {
    SECTION("encode branch node") {
        BranchNode branch{};
        // Empty branch (all zeros)
        auto encoded = encode_branch(branch);
        CHECK(!encoded.empty());

        // Branch with one child
        branch.child[0].bytes[0] = 0x01;
        branch.mask = 0x0001;
        branch.count = 1;
        auto encoded2 = encode_branch(branch);
        CHECK(encoded2.size() > encoded.size());
    }

    SECTION("encode leaf node") {
        LeafNode leaf{};
        leaf.path.len = 2;
        leaf.path[0] = 0x0A;
        leaf.path[1] = 0x0B;
        leaf.value = ByteView{reinterpret_cast<const uint8_t*>("test"), 4};

        auto encoded = encode_leaf(leaf);
        CHECK(!encoded.empty());
    }

    SECTION("encode extension node") {
        ExtensionNode ext{};
        ext.path.len = 3;
        ext.path[0] = 0x01;
        ext.path[1] = 0x02;
        ext.path[2] = 0x03;
        // Set a dummy child hash
        ext.child.bytes[0] = 0xFF;

        auto encoded = encode_ext(ext);
        CHECK(!encoded.empty());
    }
}

TEST_CASE("HP encoding") {
    SECTION("encode even-length path") {
        uint8_t path[] = {0x01, 0x02, 0x03, 0x04};
        uint8_t buffer[10];

        auto* end = encode_hp_path(buffer, path, 4, false);
        size_t encoded_len = static_cast<size_t>(end - buffer);

        CHECK(encoded_len == 3);   // 1 flag byte + 2 data bytes
        CHECK(buffer[0] == 0x00);  // Even, not leaf
    }

    SECTION("encode odd-length path") {
        uint8_t path[] = {0x01, 0x02, 0x03};
        uint8_t buffer[10];

        auto* end = encode_hp_path(buffer, path, 3, false);
        size_t encoded_len = static_cast<size_t>(end - buffer);

        CHECK(encoded_len == 2);            // 1 flag+first-nibble byte + 1 data byte
        CHECK((buffer[0] & 0x10) == 0x10);  // Odd flag set
    }

    SECTION("encode leaf path") {
        uint8_t path[] = {0x01, 0x02};
        uint8_t buffer[10];

        [[maybe_unused]] auto* end = encode_hp_path(buffer, path, 2, true);

        CHECK((buffer[0] & 0x20) == 0x20);  // Leaf flag set
    }
}

TEST_CASE("is_zero helper") {
    SECTION("zero hash") {
        bytes32 h{};
        std::memset(h.bytes, 0, 32);
        CHECK(is_zero_quick(h));
    }

    SECTION("non-zero hash") {
        bytes32 h{};
        std::memset(h.bytes, 0, 32);
        h.bytes[15] = 0x01;
        CHECK(!is_zero_quick(h));
    }
}

// =============================================================================
// GridMPT Trie Calculation Tests
// =============================================================================

TEST_CASE("GridMPT: Single insertion into empty trie") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("1000000000000000000000000000000000000000000000000000000000000000"),
        make_value("value1")
    });

    bytes32 root = grid.calc_root_from_updates(updates);
    
    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Two insertions with no common prefix") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("1000000000000000000000000000000000000000000000000000000000000000"),
        make_value("value1")
    });
    updates.push_back({
        make_key("2000000000000000000000000000000000000000000000000000000000000000"),
        make_value("value2")
    });

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Insertions with common prefix") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("ABCD100000000000000000000000000000000000000000000000000000000000"),
        make_value("value1")
    });
    updates.push_back({
        make_key("ABCD200000000000000000000000000000000000000000000000000000000000"),
        make_value("value2")
    });

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Update existing key in pre-populated trie") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    // Build initial trie: single leaf at root with full 64-nibble path
    LeafNode leaf{};
    auto key_bytes = from_hex("1234567890ABCDEF000000000000000000000000000000000000000000000000");
    
    // Convert all 32 bytes to 64 nibbles
    leaf.path.len = 0;
    for (size_t i = 0; i < key_bytes->size(); ++i) {
        leaf.path[leaf.path.len++] = (key_bytes->at(i) >> 4) & 0x0F;
        leaf.path[leaf.path.len++] = key_bytes->at(i) & 0x0F;
    }
    leaf.value = make_value("oldvalue");
    
    Bytes encoded = encode_leaf(leaf);
    bytes32 initial_root = keccak_bytes(encoded);
    mock_store.insert(initial_root, encoded);

    // Now update with same key but new value
    GridMPT grid(store, initial_root);
    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("1234567890ABCDEF000000000000000000000000000000000000000000000000"),
        make_value("newvalue")
    });

    bytes32 new_root = grid.calc_root_from_updates(updates);

    SECTION("roots are different") {
        CHECK(std::memcmp(initial_root.bytes, new_root.bytes, 32) != 0);
    }
    
    SECTION("new root is not zero") {
        CHECK(!is_zero_quick(new_root));
    }
}

TEST_CASE("GridMPT: Insert into existing trie with branch") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();
    TrieBuilder builder(mock_store);

    // Build initial trie with branch at root and 2 leaves
    // Branch at root: 1 nibble consumed
    // Leaves must have: 64 - 1 = 63 nibbles each
    
    // Create leaves with exactly 63 nibbles (can't use helper due to odd length)
    std::string leaf_path_64 = "0000000000000000000000000000000000000000000000000000000000000000";  // 64 chars
    
    LeafNode leaf1{}, leaf2{};
    auto leaf_bytes = from_hex(leaf_path_64);
    
    // Convert bytes to nibbles, use only 63
    leaf1.path.len = 0;
    leaf2.path.len = 0;
    for (size_t i = 0; i < leaf_bytes->size() && leaf1.path.len < 63; ++i) {
        leaf1.path[leaf1.path.len] = (leaf_bytes->at(i) >> 4) & 0x0F;
        leaf2.path[leaf2.path.len] = (leaf_bytes->at(i) >> 4) & 0x0F;
        if (++leaf1.path.len >= 63) break;
        leaf1.path[leaf1.path.len] = leaf_bytes->at(i) & 0x0F;
        leaf2.path[leaf2.path.len] = leaf_bytes->at(i) & 0x0F;
        if (++leaf1.path.len >= 63) break;
    }
    leaf1.path.len = 63;
    leaf2.path.len = 63;
    
    leaf1.value = make_value("value1");
    leaf2.value = make_value("value2");
    
    Bytes enc1 = encode_leaf(leaf1);
    Bytes enc2 = encode_leaf(leaf2);
    bytes32 hash1 = keccak_bytes(enc1);
    bytes32 hash2 = keccak_bytes(enc2);
    mock_store.insert(hash1, enc1);
    mock_store.insert(hash2, enc2);
    
    bytes32 branch_root = builder.make_branch({
        {0x01, hash1},
        {0x02, hash2}
    });

    // Now insert a new key starting with 0x03
    // Path: 0x03 + 63 more nibbles = 64 total
    GridMPT grid(store, branch_root);
    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("3000000000000000000000000000000000000000000000000000000000000000"),
        make_value("value3")
    });

    bytes32 new_root = grid.calc_root_from_updates(updates);

    SECTION("new root is different from old") {
        CHECK(std::memcmp(branch_root.bytes, new_root.bytes, 32) != 0);
    }
    
    SECTION("new root is not zero") {
        CHECK(!is_zero_quick(new_root));
    }
}

TEST_CASE("GridMPT: Insert into trie with extension") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();
    TrieBuilder builder(mock_store);

    // Build: Extension(ABCD, 4 nibbles) -> Branch(1 nibble) -> 2 leaves(59 nibbles each)
    // Total path: 4 + 1 + 59 = 64 nibbles ✓
    
    // 59 nibbles = 59 hex chars, but from_hex needs even length
    // So use 60 chars (60 nibbles) and manually trim to 59
    std::string leaf_path_60 = "000000000000000000000000000000000000000000000000000000000000";  // 60 chars
    
    // Manually create leaves with exactly 59 nibbles
    LeafNode leaf1{}, leaf2{};
    auto leaf_bytes = from_hex(leaf_path_60);
    
    // Convert 30 bytes to 60 nibbles, then use only 59
    leaf1.path.len = 0;
    leaf2.path.len = 0;
    for (size_t i = 0; i < leaf_bytes->size() && leaf1.path.len < 59; ++i) {
        leaf1.path[leaf1.path.len] = (leaf_bytes->at(i) >> 4) & 0x0F;
        leaf2.path[leaf2.path.len] = (leaf_bytes->at(i) >> 4) & 0x0F;
        if (++leaf1.path.len >= 59) break;
        leaf1.path[leaf1.path.len] = leaf_bytes->at(i) & 0x0F;
        leaf2.path[leaf2.path.len] = leaf_bytes->at(i) & 0x0F;
        if (++leaf1.path.len >= 59) break;
    }
    // Ensure exactly 59 nibbles
    leaf1.path.len = 59;
    leaf2.path.len = 59;
    
    leaf1.value = make_value("val1");
    leaf2.value = make_value("val2");
    
    Bytes enc1 = encode_leaf(leaf1);
    Bytes enc2 = encode_leaf(leaf2);
    bytes32 hash1 = keccak_bytes(enc1);
    bytes32 hash2 = keccak_bytes(enc2);
    mock_store.insert(hash1, enc1);
    mock_store.insert(hash2, enc2);
    
    bytes32 branch = builder.make_branch({
        {0x01, hash1},
        {0x02, hash2}
    });
    
    bytes32 ext_root = builder.make_extension("ABCD", branch);

    // Insert key that splits the extension at position 2 (AB|CD)
    // The new key is AB + 00 + (62 more nibbles) = 64 total
    GridMPT grid(store, ext_root);
    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("AB00000000000000000000000000000000000000000000000000000000000000"),
        make_value("value3")
    });

    bytes32 new_root = grid.calc_root_from_updates(updates);

    SECTION("extension was split") {
        CHECK(std::memcmp(ext_root.bytes, new_root.bytes, 32) != 0);
    }
    
    SECTION("new root is not zero") {
        CHECK(!is_zero_quick(new_root));
    }
}

TEST_CASE("GridMPT: Leaf collision and split") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("AAAAAAAAAAAAAAAA000000000000000000000000000000000000000000000000"),
        make_value("value1")
    });
    updates.push_back({
        make_key("AAAAAAAAAAAAAAAA100000000000000000000000000000000000000000000000"),
        make_value("value2")
    });

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Extension node split") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("ABCD000000000000000000000000000000000000000000000000000000000000"),
        make_value("value1")
    });
    updates.push_back({
        make_key("ABCD100000000000000000000000000000000000000000000000000000000000"),
        make_value("value2")
    });
    updates.push_back({
        make_key("AB00000000000000000000000000000000000000000000000000000000000000"),
        make_value("value3")
    });

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Multiple updates in sorted order") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    for (int i = 0; i < 10; ++i) {
        bytes32 key{};
        key.bytes[0] = static_cast<uint8_t>(i);
        updates.push_back({key, make_value("value" + std::to_string(i))});
    }

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Adjacent keys") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    bytes32 key1{}, key2{};
    std::memset(key1.bytes, 0, 32);
    std::memset(key2.bytes, 0, 32);
    key1.bytes[31] = 0x00;
    key2.bytes[31] = 0x01;

    updates.push_back({key1, make_value("value1")});
    updates.push_back({key2, make_value("value2")});

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Empty update list") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root should be empty") {
        CHECK(root == kEmptyRoot);
    }
}

TEST_CASE("GridMPT: Complex scenario with mixed operations") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    GridMPT grid(store, kEmptyRoot);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("1000000000000000000000000000000000000000000000000000000000000000"),
        make_value("v1")
    });
    updates.push_back({
        make_key("1100000000000000000000000000000000000000000000000000000000000000"),
        make_value("v2")
    });
    updates.push_back({
        make_key("1110000000000000000000000000000000000000000000000000000000000000"),
        make_value("v3")
    });
    updates.push_back({
        make_key("1111000000000000000000000000000000000000000000000000000000000000"),
        make_value("v4")
    });
    updates.push_back({
        make_key("2000000000000000000000000000000000000000000000000000000000000000"),
        make_value("v5")
    });

    bytes32 root = grid.calc_root_from_updates(updates);

    SECTION("root is not zero") {
        CHECK(!is_zero_quick(root));
    }
}

TEST_CASE("GridMPT: Deterministic root hash") {
    MockNodeStore mock_store1, mock_store2;
    auto store1 = mock_store1.make_store();
    auto store2 = mock_store2.make_store();

    std::vector<TrieNodeFlat> updates;
    updates.push_back({
        make_key("ABCD000000000000000000000000000000000000000000000000000000000000"),
        make_value("value1")
    });
    updates.push_back({
        make_key("ABCD100000000000000000000000000000000000000000000000000000000000"),
        make_value("value2")
    });

    GridMPT grid1(store1, kEmptyRoot);
    bytes32 root1 = grid1.calc_root_from_updates(updates);

    GridMPT grid2(store2, kEmptyRoot);
    bytes32 root2 = grid2.calc_root_from_updates(updates);

    SECTION("same inputs produce same root") {
        CHECK(std::memcmp(root1.bytes, root2.bytes, 32) == 0);
    }
}

TEST_CASE("GridMPT: Incremental updates") {
    MockNodeStore mock_store;
    auto store = mock_store.make_store();

    bytes32 root = kEmptyRoot;

    {
        GridMPT grid(store, root);
        std::vector<TrieNodeFlat> updates;
        updates.push_back({
            make_key("1000000000000000000000000000000000000000000000000000000000000000"),
            make_value("v1")
        });
        root = grid.calc_root_from_updates(updates);
    }

    bytes32 root_after_1 = root;
    CHECK(!is_zero_quick(root_after_1));

    {
        GridMPT grid(store, root);
        std::vector<TrieNodeFlat> updates;
        updates.push_back({
            make_key("2000000000000000000000000000000000000000000000000000000000000000"),
            make_value("v2")
        });
        root = grid.calc_root_from_updates(updates);
    }

    bytes32 root_after_2 = root;

    SECTION("incremental updates change root") {
        CHECK(std::memcmp(root_after_1.bytes, root_after_2.bytes, 32) != 0);
    }

    SECTION("final root is not zero") {
        CHECK(!is_zero_quick(root_after_2));
    }
}

}  // namespace silkworm::mpt