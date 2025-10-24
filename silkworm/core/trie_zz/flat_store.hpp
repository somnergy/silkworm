#include <cstring>
#include <unordered_map>  // must come after evmc.hpp so operator== is visible

#include "node_store_i.hpp"  // includes evmc.hpp which defines operator== for bytes32

namespace silkworm::mpt {

// Custom hasher for bytes32
struct FastHash {
    size_t operator()(const bytes32& key) const noexcept {
        uint32_t h;
        std::memcpy(&h, key.bytes, sizeof(uint32_t));
        return h * 2654435761u;  // Knuth's multiplicative hash
    }
};


class FlatNodeStore : public NodeStore {
  public:
    std::unordered_map<bytes32, Bytes, FastHash> storage_;

    FlatNodeStore() {
        storage_.reserve(4096);  // Pre-allocate for ~4k entries
    }

    void clear() { storage_.clear(); }
    size_t size() const { return storage_.size(); }
    // Populate the store from RLP-encoded trie nodes
    // Layout: [rlp{32-byte hash, bytes}, rlp{32-byte hash, bytes}, ...]
    void populate_from_rlp(ByteView trie_rlp);

    // Helper to manually insert nodes for testing
    void insert(const bytes32& hash, const Bytes& rlp) {
        storage_[hash] = rlp;
    }

    ByteView get_rlp(const bytes32& hash) const override {
        auto it = storage_.find(hash);
        if (it == storage_.end()) {
            static Bytes empty;
            return ByteView{empty};
        }
        return ByteView{it->second};
    }

    void put_rlp(const bytes32& hash, const Bytes& rlp) override {
        storage_[hash] = rlp;
    }
};

}  // namespace silkworm::mpt