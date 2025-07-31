// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/dev/common/ecc_key_pair.hpp>

#include "expected_state.hpp"

namespace silkworm::cmd::state_transition {

StateTransition::StateTransition(const std::string& json_str, const bool terminate_on_error, const bool show_diagnostics) noexcept
    : terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
    nlohmann::json base_json;
    base_json = nlohmann::json::parse(json_str);
    auto test_object = base_json.begin();
    test_name_ = test_object.key();
    test_data_ = test_object.value();
}

StateTransition::StateTransition(const bool terminate_on_error, const bool show_diagnostics) noexcept
    : terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
    nlohmann::json base_json;
    const std::string json_str = R"json(
{"add": {"_info": {"comment": "Ori Pomerantz qbzzt1@gmail.com","filling-rpc-server": "evm version 1.11.4-unstable-e14043db-20230308","filling-tool-version": "retesteth-0.3.0-shanghai+commit.fd2c0a83.Linux.g++","generatedTestHash": "f486c80e808d34507133961cbd17c5e0f9ec049879dd3f7cc78a9eb55ac63226","labels": {"0": "add_neg1_neg1","1": "add_neg1_4","2": "add_neg1_1","3": "add_0_0","4": "add_1_neg1"},"lllcversion": "Version: 0.5.14-develop.2022.7.30+commit.a096d7a9.Linux.g++","solidity": "Version: 0.8.17+commit.8df45f5f.Linux.g++","source": "src/GeneralStateTestsFiller/VMTests/vmArithmeticTest/addFiller.yml","sourceHash": "78afea990a2d534831acc4883b9ff6e81d560091942db7234232d68fdbf1c33e"},"env": {"currentBaseFee": "0x0a","currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba","currentDifficulty": "0x020000","currentGasLimit": "0x05f5e100","currentNumber": "0x01","currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000","currentTimestamp": "0x03e8","previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6"},"post": {"Shanghai": [{"hash": "0x6e9dccb57a15e2885ff1193da0db98cbaaac218bf3a0abeb0c3ceff966de2830","indexes": {"data": 0,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000001ba0e8ff56322287185f6afd3422a825b47bf5c1a4ccf0dc0389cdc03f7c1c32b7eaa0776b02f9f5773238d3ff36b74a123f409cd6420908d7855bbe4c8ff63e00d698"},{"hash": "0x1a3420dfb2280397c1b81ff159bd4d6eddc12d7e333e82a01fd4afafad3b2ae4","indexes": {"data": 1,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000011ba02c5e81a024dd0f6fb773c8787fa46ab5eb55cb73df83562e6ddbe9106a3df7f6a029437b9a23e45bbfce086f2ddaa98b1e9e6914d7e58e2c5a128310042b332f89"},{"hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02","indexes": {"data": 2,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000021ba0fc37ad4eb0633eb18f2b7867bacbe994a2ffcbb04a71e394e6e76041f6ce216fa03b1b415a5c386d8de9e16be9fdc188234b80a0dec99922d03c240f2e463053e3"},{"hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02","indexes": {"data": 3,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000031ba0f06eb219c5dba98711a9a2678339f64d172bfac289a5c43a0018d3917be8dc2aa0147bd7a6ee30217e63cbddc28b0e72f115da754d8916b87992aa27ed00eb105e"},{"hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02","indexes": {"data": 4,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000041ba0c148a101aa54703ff0e949441bdba90b1972a16c338f7f9a24b07f0313cd49d6a028cb82229b8a57e2048761d6fa5060c5b459f000d4e218de1372c1df9cfa171e"}]},"pre": {"0x0000000000000000000000000000000000000100": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000101": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000102": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x60017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000103": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x600060000160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000104": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60010160005500","nonce": "0x00","storage": {}},"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x","nonce": "0x00","storage": {}},"0xcccccccccccccccccccccccccccccccccccccccc": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x600060006000600060006004356101000162fffffff100","nonce": "0x00","storage": {}}},"transaction": {"data": ["0x693c61390000000000000000000000000000000000000000000000000000000000000000","0x693c61390000000000000000000000000000000000000000000000000000000000000001","0x693c61390000000000000000000000000000000000000000000000000000000000000002","0x693c61390000000000000000000000000000000000000000000000000000000000000003","0x693c61390000000000000000000000000000000000000000000000000000000000000004"],"gasLimit": ["0x04c4b400"],"gasPrice": "0x0a","nonce": "0x00","secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8","sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","to": "0xcccccccccccccccccccccccccccccccccccccccc","value": ["0x01"]}}}
    )json";
    base_json = nlohmann::json::parse(json_str);
    auto test_object = base_json.begin();
    test_name_ = test_object.key();
    test_data_ = test_object.value();
}

std::vector<ExpectedState> StateTransition::get_expected_states() {
    std::vector<ExpectedState> expected_states;
    auto post_items = test_data_.at("post").items();
    // std::cout << "get_expected_states:test_data" << post_items;
    for (const auto& post_state : post_items) {
        // std::cout << "get_expected_states: test_data_.at(\"post\").items(i)" << post_state << "\n";
        auto data = post_state.value();
        // std::cout << "get_expected_states:items(i).value().array:" << data;
        const std::string& key = post_state.key();
        expected_states.emplace_back(data[0], key);
    }

    return expected_states;
}


std::string StateTransition::get_env(const std::string& key) {
    return test_data_.at("env").at(key);
}

bool StateTransition::contains_env(const std::string& key) {
    return test_data_.at("env").contains(key);
}

evmc::address StateTransition::to_evmc_address(const std::string& address) {
    evmc::address out;
    if (!address.empty()) {
        out = hex_to_address(address);
    }

    return out;
}

Block StateTransition::get_block(InMemoryState& state, ChainConfig& chain_config) {
    auto block = Block();

    block.header.beneficiary = to_evmc_address(get_env("currentCoinbase"));

    block.header.gas_limit = std::stoull(get_env("currentGasLimit"), nullptr, /*base=*/16);
    block.header.number = std::stoull(get_env("currentNumber"), nullptr, /*base=*/16);
    block.header.timestamp = std::stoull(get_env("currentTimestamp"), nullptr, /*base=*/16);
    block.header.parent_hash = to_bytes32(from_hex(get_env("previousHash")).value_or(Bytes{}));

    if (contains_env("currentRandom")) {
        block.header.prev_randao = to_bytes32(from_hex(get_env("currentRandom")).value_or(Bytes{}));
    }

    const evmc_revision rev{chain_config.revision(block.header.number, block.header.timestamp)};

    // set difficulty only for revisions before The Merge
    // current block difficulty cannot fall below minimum: https://eips.ethereum.org/EIPS/eip-2
    static constexpr uint64_t kMinDifficulty{0x20000};
    if (!chain_config.terminal_total_difficulty.has_value()) {
        block.header.difficulty = intx::from_string<intx::uint256>(get_env("currentDifficulty"));
        if (block.header.difficulty < kMinDifficulty && rev <= EVMC_LONDON) {
            block.header.difficulty = kMinDifficulty;
        }
    }

    if (contains_env("currentBaseFee") && rev >= EVMC_LONDON) {
        block.header.base_fee_per_gas = intx::from_string<intx::uint256>(get_env("currentBaseFee"));
    }

    if (rev >= EVMC_SHANGHAI) {
        block.withdrawals = std::vector<Withdrawal>{};
        block.header.withdrawals_root = kEmptyRoot;
    }

    block.header.transactions_root = protocol::compute_transaction_root(block);
    block.header.ommers_hash = kEmptyListHash;

    auto parent_block = Block();
    parent_block.header.gas_limit = block.header.gas_limit;
    parent_block.header.gas_used = parent_block.header.gas_limit / protocol::kElasticityMultiplier;
    parent_block.header.number = block.header.number - 1;
    parent_block.header.base_fee_per_gas = block.header.base_fee_per_gas;
    parent_block.header.ommers_hash = kEmptyListHash;
    parent_block.header.difficulty = intx::from_string<intx::uint256>(get_env("currentDifficulty"));
    state.insert_block(parent_block, block.header.parent_hash);

    return block;
}

std::unique_ptr<evmc::address> StateTransition::private_key_to_address(const std::string& private_key) {
    /// Example
    // private key: 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8
    // public key : 043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3
    // address    : 0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B

    auto private_key_bytes = from_hex(private_key).value();

    auto pair = sentry::EccKeyPair(private_key_bytes);

    uint8_t out[kAddressLength];
    auto public_key_hash = keccak256(pair.public_key().serialized());
    std::memcpy(out, public_key_hash.bytes + 12, sizeof(out));

    return std::make_unique<evmc::address>(bytes_to_address(out));
}

Transaction StateTransition::get_transaction(const ExpectedSubState& expected_sub_state) {
    Transaction txn;
    // auto j_transaction = test_data_["transaction"];
    // // std::cout << "J_transaction" << j_transaction.dump();

    // txn.nonce = std::stoull(j_transaction.at("nonce").get<std::string>(), nullptr, 16);
    // txn.set_sender(*private_key_to_address(j_transaction["secretKey"]));

    // const auto to_address = j_transaction.at("to").get<std::string>();
    // if (!to_address.empty()) {
    //     txn.to = to_evmc_address(to_address);
    // }
    // //        std::cout << "from address: " << to_hex(txn.from.value()) << std::endl;

    // if (j_transaction.contains("gasPrice")) {
    //     txn.type = TransactionType::kLegacy;
    //     txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
    //     txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
    // } else {
    //     txn.type = TransactionType::kDynamicFee;
    //     txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxFeePerGas").get<std::string>());
    //     txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxPriorityFeePerGas").get<std::string>());
    // }

    if (expected_sub_state.dataIndex >= 5) {
    //     // throw std::runtime_error("data index out of range");
    }

    // if (expected_sub_state.dataIndex >= j_transaction.at("data").size()) {
    // //     // throw std::runtime_error("data index out of range");
    // }
    // txn.data = from_hex(j_transaction.at("data").at(expected_sub_state.dataIndex).get<std::string>()).value();

    // if (expected_sub_state.gasIndex >= j_transaction.at("gasLimit").size()) {
    //     // throw std::runtime_error("gas limit index out of range");
    // }
    // txn.gas_limit = std::stoull(j_transaction.at("gasLimit").at(expected_sub_state.gasIndex).get<std::string>(), nullptr, 16);

    // if (expected_sub_state.valueIndex >= j_transaction.at("value").size()) {
    //     // throw std::runtime_error("value index out of range");
    // }
    // auto value_str = j_transaction.at("value").at(expected_sub_state.valueIndex).get<std::string>();
    // // in case of bigint, set max value; compatible with all test cases so far
    // txn.value = (value_str.starts_with("0x:bigint ")) ? std::numeric_limits<intx::uint256>::max() : intx::from_string<intx::uint256>(value_str);

    // if (j_transaction.contains("accessLists")) {
    //     auto j_access_list = j_transaction.at("accessLists").at(expected_sub_state.dataIndex);

    //     for (const auto& j_access_entry : j_access_list.items()) {
    //         AccessListEntry entry;
    //         entry.account = to_evmc_address(j_access_entry.value().at("address"));

    //         for (const auto& j_storage_key : j_access_entry.value().at("storageKeys").items()) {
    //             if (j_storage_key.value().is_string()) {
    //                 auto hex_storage = from_hex(j_storage_key.value().get<std::string>());
    //                 entry.storage_keys.emplace_back(to_bytes32(hex_storage.value()));
    //             }
    //         }

    //         txn.access_list.emplace_back(entry);
    //     }

    //     if (txn.type == TransactionType::kLegacy) {
    //         txn.type = TransactionType::kAccessList;
    //     }
    // }

    return txn;
}

void StateTransition::get_transaction2(const ExpectedSubState& expected_sub_state) {
    Transaction txn;
    // auto j_transaction = test_data_["transaction"];
    // // std::cout << "J_transaction" << j_transaction.dump();

    // txn.nonce = std::stoull(j_transaction.at("nonce").get<std::string>(), nullptr, 16);
    // txn.set_sender(*private_key_to_address(j_transaction["secretKey"]));

    // const auto to_address = j_transaction.at("to").get<std::string>();
    // if (!to_address.empty()) {
    //     txn.to = to_evmc_address(to_address);
    // }
    // //        std::cout << "from address: " << to_hex(txn.from.value()) << std::endl;

    // if (j_transaction.contains("gasPrice")) {
    //     txn.type = TransactionType::kLegacy;
    //     txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
    //     txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
    // } else {
    //     txn.type = TransactionType::kDynamicFee;
    //     txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxFeePerGas").get<std::string>());
    //     txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxPriorityFeePerGas").get<std::string>());
    // }

    if (expected_sub_state.dataIndex >= 5) {
    //     // throw std::runtime_error("data index out of range");
    }

    // if (expected_sub_state.dataIndex >= j_transaction.at("data").size()) {
    // //     // throw std::runtime_error("data index out of range");
    // }
    // txn.data = from_hex(j_transaction.at("data").at(expected_sub_state.dataIndex).get<std::string>()).value();

    // if (expected_sub_state.gasIndex >= j_transaction.at("gasLimit").size()) {
    //     // throw std::runtime_error("gas limit index out of range");
    // }
    // txn.gas_limit = std::stoull(j_transaction.at("gasLimit").at(expected_sub_state.gasIndex).get<std::string>(), nullptr, 16);

    // if (expected_sub_state.valueIndex >= j_transaction.at("value").size()) {
    //     // throw std::runtime_error("value index out of range");
    // }
    // auto value_str = j_transaction.at("value").at(expected_sub_state.valueIndex).get<std::string>();
    // // in case of bigint, set max value; compatible with all test cases so far
    // txn.value = (value_str.starts_with("0x:bigint ")) ? std::numeric_limits<intx::uint256>::max() : intx::from_string<intx::uint256>(value_str);

    // if (j_transaction.contains("accessLists")) {
    //     auto j_access_list = j_transaction.at("accessLists").at(expected_sub_state.dataIndex);

    //     for (const auto& j_access_entry : j_access_list.items()) {
    //         AccessListEntry entry;
    //         entry.account = to_evmc_address(j_access_entry.value().at("address"));

    //         for (const auto& j_storage_key : j_access_entry.value().at("storageKeys").items()) {
    //             if (j_storage_key.value().is_string()) {
    //                 auto hex_storage = from_hex(j_storage_key.value().get<std::string>());
    //                 entry.storage_keys.emplace_back(to_bytes32(hex_storage.value()));
    //             }
    //         }

    //         txn.access_list.emplace_back(entry);
    //     }

    //     if (txn.type == TransactionType::kLegacy) {
    //         txn.type = TransactionType::kAccessList;
    //     }
    // }

    // return txn;
}

void StateTransition::validate_transition(const Receipt& receipt, const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const InMemoryState& state) {
    if (expected_sub_state.exceptionExpected) {
        if (receipt.success) {
            // print_error_message(expected_state, expected_sub_state, "Failed: Exception expected");
            ++failed_count_;
        }
    }

    if (expected_state.fork_name().length() == 0) {

    }

    if (state.state_root_hash() != expected_sub_state.stateHash) {
        // print_error_message(expected_state, expected_sub_state, "Failed: State root hash does not match");
        ++failed_count_;
    } else {
        Bytes encoded;
        rlp::encode(encoded, receipt.logs);
        if (std::bit_cast<evmc_bytes32>(keccak256(encoded)) != expected_sub_state.logsHash) {
            // print_error_message(expected_state, expected_sub_state, "Failed: Logs hash does not match");
            ++failed_count_;
        } else {
            // print_diagnostic_message(expected_state, expected_sub_state, "OK");
        }
    }
}

/*
//  * This function is used to clean up the state after a failed block execution.
//  * Certain post-processing would be a part of the execute_transaction() function,
//  * but since the validation failed, we need to do it manually.
//  */
void cleanup_error_block(Block& block, ExecutionProcessor& processor, const evmc_revision rev) {
    if (rev >= EVMC_SHANGHAI) {
        processor.evm().state().access_account(block.header.beneficiary);
    }
    processor.evm().state().add_to_balance(block.header.beneficiary, 0);
    processor.evm().state().finalize_transaction(rev);
    processor.evm().state().write_to_db(block.header.number);
}

void StateTransition::run() {
    failed_count_ = 0;
    total_count_ = 0;
    if (test_name_.length() == 0) {

    }
    // get_expected_states();
    for (auto& expected_state : get_expected_states()) {
        // if (expected_state.fork_name() == expected_state.fork_name()) {
        //     continue;
        // }
    //     // if (expected_state == nullptr) {
    //     //     continue;
    //     // }
        for (const auto& expected_sub_state : expected_state.get_sub_states()) {

            if (expected_sub_state.exceptionExpected) {

            }

            ++total_count_;
            auto config = expected_state.get_config();
            auto rule_set = protocol::rule_set_factory(config);
            if (rule_set == nullptr) {

            }
            auto state = read_genesis_allocation(test_data_["pre"]);
            // state.unwind_state_changes(0);
            auto block = get_block(state, config);
            if (block.header.difficulty.num_bits == 0) {

            }
            get_transaction2(expected_sub_state);

            // auto txn = get_transaction(expected_sub_state);
            // if (txn.chain_id.value().num_bits == 0) {

            // }

            // ExecutionProcessor processor{block, *rule_set, state, config, true};

            // if (processor.available_gas() == 0) {

            // }
            // Receipt receipt;

            // const evmc_revision rev{config.revision(block.header.number, block.header.timestamp)};

            // auto pre_block_validation = rule_set->pre_validate_block_body(block, state);
            // auto block_validation = rule_set->validate_block_header(block.header, state, true);
            // auto pre_txn_validation = protocol::pre_validate_transaction(txn, rev, config.chain_id, block.header.base_fee_per_gas, block.header.blob_gas_price());
            // auto txn_validation = protocol::validate_transaction(txn, processor.evm().state(), processor.available_gas());

            // if (pre_block_validation == ValidationResult::kOk &&
            //     block_validation == ValidationResult::kOk &&
            //     pre_txn_validation == ValidationResult::kOk &&
            //     txn_validation == ValidationResult::kOk) {
            //     // processor.execute_transaction(txn, receipt);
            //     // processor.evm().state().write_to_db(block.header.number);
            // } else {
            //     // INCORRECT PATH =============
            //     // processor.execute_transaction(txn, receipt);
            //     // processor.evm().state().write_to_db(block.header.number);
            //     // receipt.success = true;
            //     // ============================
            // //     cleanup_error_block(block, processor, rev);
            //     receipt.success = false;
            // }

            // validate_transition(receipt, expected_state, expected_sub_state, state);
        }
    }

    if (show_diagnostics_) {
        // std::cout doesn't play well with risv
    }
}

void sample_run() {
    const std::string json_str = R"json(
{"add": {"_info": {"comment": "Ori Pomerantz qbzzt1@gmail.com","filling-rpc-server": "evm version 1.11.4-unstable-e14043db-20230308","filling-tool-version": "retesteth-0.3.0-shanghai+commit.fd2c0a83.Linux.g++","generatedTestHash": "f486c80e808d34507133961cbd17c5e0f9ec049879dd3f7cc78a9eb55ac63226","labels": {"0": "add_neg1_neg1","1": "add_neg1_4","2": "add_neg1_1","3": "add_0_0","4": "add_1_neg1"},"lllcversion": "Version: 0.5.14-develop.2022.7.30+commit.a096d7a9.Linux.g++","solidity": "Version: 0.8.17+commit.8df45f5f.Linux.g++","source": "src/GeneralStateTestsFiller/VMTests/vmArithmeticTest/addFiller.yml","sourceHash": "78afea990a2d534831acc4883b9ff6e81d560091942db7234232d68fdbf1c33e"},"env": {"currentBaseFee": "0x0a","currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba","currentDifficulty": "0x020000","currentGasLimit": "0x05f5e100","currentNumber": "0x01","currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000","currentTimestamp": "0x03e8","previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6"},"post": {"Shanghai": [{"hash": "0x6e9dccb57a15e2885ff1193da0db98cbaaac218bf3a0abeb0c3ceff966de2830","indexes": {"data": 0,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000001ba0e8ff56322287185f6afd3422a825b47bf5c1a4ccf0dc0389cdc03f7c1c32b7eaa0776b02f9f5773238d3ff36b74a123f409cd6420908d7855bbe4c8ff63e00d698"},{"hash": "0x1a3420dfb2280397c1b81ff159bd4d6eddc12d7e333e82a01fd4afafad3b2ae4","indexes": {"data": 1,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000011ba02c5e81a024dd0f6fb773c8787fa46ab5eb55cb73df83562e6ddbe9106a3df7f6a029437b9a23e45bbfce086f2ddaa98b1e9e6914d7e58e2c5a128310042b332f89"},{"hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02","indexes": {"data": 2,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000021ba0fc37ad4eb0633eb18f2b7867bacbe994a2ffcbb04a71e394e6e76041f6ce216fa03b1b415a5c386d8de9e16be9fdc188234b80a0dec99922d03c240f2e463053e3"},{"hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02","indexes": {"data": 3,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000031ba0f06eb219c5dba98711a9a2678339f64d172bfac289a5c43a0018d3917be8dc2aa0147bd7a6ee30217e63cbddc28b0e72f115da754d8916b87992aa27ed00eb105e"},{"hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02","indexes": {"data": 4,"gas": 0,"value": 0},"logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","txbytes": "0xf885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000041ba0c148a101aa54703ff0e949441bdba90b1972a16c338f7f9a24b07f0313cd49d6a028cb82229b8a57e2048761d6fa5060c5b459f000d4e218de1372c1df9cfa171e"}]},"pre": {"0x0000000000000000000000000000000000000100": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000101": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000102": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x60017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000103": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x600060000160005500","nonce": "0x00","storage": {}},"0x0000000000000000000000000000000000000104": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60010160005500","nonce": "0x00","storage": {}},"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x","nonce": "0x00","storage": {}},"0xcccccccccccccccccccccccccccccccccccccccc": {"balance": "0x0ba1a9ce0ba1a9ce","code": "0x600060006000600060006004356101000162fffffff100","nonce": "0x00","storage": {}}},"transaction": {"data": ["0x693c61390000000000000000000000000000000000000000000000000000000000000000","0x693c61390000000000000000000000000000000000000000000000000000000000000001","0x693c61390000000000000000000000000000000000000000000000000000000000000002","0x693c61390000000000000000000000000000000000000000000000000000000000000003","0x693c61390000000000000000000000000000000000000000000000000000000000000004"],"gasLimit": ["0x04c4b400"],"gasPrice": "0x0a","nonce": "0x00","secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8","sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","to": "0xcccccccccccccccccccccccccccccccccccccccc","value": ["0x01"]}}}
    )json";
    auto state_transition = StateTransition(json_str, false, true);
    // state_transition.run();
}


    // Dog::Dog(const bool terminate_on_error, const bool show_diagnostics) noexcept
    //     : terminate_on_error_{terminate_on_error},
    //     show_diagnostics_{show_diagnostics} {
    // }

    // Dog::Dog(const std::string& file_path) noexcept {
    //         if (file_path.length() == 0) {
            
    //         }
    // }
    // Dog::Dog(const std::string& json_str, bool terminate_on_error, bool show_diagnostics) noexcept 
    //         : terminate_on_error_{terminate_on_error},
    //     show_diagnostics_{show_diagnostics} {
    //         if (json_str.length() == 0) {

    //         }
    // }
    // int Dog::getLives() {
    //     return lives;
    // }
    // void Dog::doStuff() {
    //     if (show_diagnostics_) {
    //         test_name_  = "moha";
    //     }
    // }

}  // namespace silkworm::cmd::state_transition



// COUT can't be executed on rv32im ::: ====>


// void StateTransition::print_error_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
//     if (terminate_on_error_) {
//         throw std::runtime_error(message);
//     }
//     // print_message(expected_state, expected_sub_state, message);
// }

// void StateTransition::print_diagnostic_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
//     if (show_diagnostics_) {
//         print_message(expected_state, expected_sub_state, message);
//     }
// }

// void StateTransition::print_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
//     // std::cout << "[" << test_name_ << ":" << expected_state.fork_name() << ":" << expected_sub_state.index << "] " << message << std::endl;
// }
