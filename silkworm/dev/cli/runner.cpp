// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>

// #include <CLI/CLI.hpp>

#include "../state_transition.hpp"

// void execute_test(const std::string& json_str, bool terminate_flag, bool diagnostics_flag);
using namespace silkworm::cmd::state_transition;

int main() {
    try {
        const std::string json_str = R"json(
{
    "1": {
        "env": {
            "currentBaseFee": "0x0a",
            "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "currentDifficulty": "0x020000",
            "currentGasLimit": "0x05f5e100",
            "currentNumber": "0x01",
            "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
            "currentTimestamp": "0x03e8",
            "previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6"
        },
        "post": {
            "Shanghai": [
                {
                    "hash": "0x6e9dccb57a15e2885ff1193da0db98cbaaac218bf3a0abeb0c3ceff966de2830",
                    "indexes": {
                        "data": 0,
                        "gas": 0,
                        "value": 0
                    },
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                }
            ]
        },
        "pre": {
            "0x0000000000000000000000000000000000000100": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
                "nonce": "0x00",
                "storage": {}
            },
            "0x0000000000000000000000000000000000000101": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
                "nonce": "0x00",
                "storage": {}
            },
            "0x0000000000000000000000000000000000000102": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x60017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
                "nonce": "0x00",
                "storage": {}
            },
            "0x0000000000000000000000000000000000000103": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x600060000160005500",
                "nonce": "0x00",
                "storage": {}
            },
            "0x0000000000000000000000000000000000000104": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60010160005500",
                "nonce": "0x00",
                "storage": {}
            },
            "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x",
                "nonce": "0x00",
                "storage": {}
            },
            "0xcccccccccccccccccccccccccccccccccccccccc": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x600060006000600060006004356101000162fffffff100",
                "nonce": "0x00",
                "storage": {}
            }
        },
        "transaction": {
            "data": [
                "0x693c61390000000000000000000000000000000000000000000000000000000000000000",
                "0x693c61390000000000000000000000000000000000000000000000000000000000000001",
                "0x693c61390000000000000000000000000000000000000000000000000000000000000002",
                "0x693c61390000000000000000000000000000000000000000000000000000000000000003",
                "0x693c61390000000000000000000000000000000000000000000000000000000000000004"
            ],
            "gasLimit": [
                "0x04c4b400"
            ],
            "gasPrice": "0x0a",
            "nonce": "0x00",
            "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "to": "0xcccccccccccccccccccccccccccccccccccccccc",
            "value": [
                "0x01"
            ]
        }
    }
}
)json";
        auto state_transition = StateTransition(json_str, false, true);
        state_transition.run();
    } catch (const std::exception& e) {
        // code to handle exceptions of type std::exception and its derived classes
        const auto desc = e.what();
        std::cerr << "Exception: " << desc << std::endl;
    } catch (...) {
        // code to handle any other type of exception
        std::cerr << "An unknown exception occurred" << std::endl;
    }
}
