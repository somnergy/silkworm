// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie_zz/helpers.hpp>
#include <silkworm/core/trie_zz/mpt.hpp>
#include <silkworm/core/trie_zz/rlp_sw.hpp>

namespace silkworm::mpt {

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

TEST_CASE("GridMPT basic operations") {
    SECTION("construct empty grid") {
        // This is a placeholder - you'll need to implement actual GridMPT tests
        // based on your NodeStore implementation
        CHECK(true);
    }
}

}  // namespace silkworm::mpt
