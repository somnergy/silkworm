// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecdsa.h"

#include <evmone_precompiles/secp256k1.hpp>

bool silkworm_recover_address(uint8_t out[20], const uint8_t message[32], const uint8_t signature[64],
                              uint8_t recovery_id) {
    ethash::hash256 msg_hash;
    std::memcpy(msg_hash.bytes, message, 32);
    const auto opt_address = evmmax::secp256k1::ecrecover(msg_hash,
                                                          intx::be::unsafe::load<intx::uint256>(&signature[0]),
                                                          intx::be::unsafe::load<intx::uint256>(&signature[32]),
                                                          recovery_id != 0);
    if (!opt_address) {
        return false;
    }
    std::memcpy(out, opt_address->bytes, 20);
    return true;
}
