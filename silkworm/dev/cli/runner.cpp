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
            "baseFeePerGas": "0x0a",
            "miner": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "difficulty": "0x020000",
            "gasLimit": "0x05f5e100",
            "number": "0x01",
            "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
            "timestamp": "0x03e8",
            "parentHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6"
        },
        "transactions": {
            "Shanghai": [
                {
                    "hash": "0x6e9dccb57a15e2885ff1193da0db98cbaaac218bf3a0abeb0c3ceff966de2830",
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "data": "0x693c61390000000000000000000000000000000000000000000000000000000000000000",
                    "gasLimit": "0x04c4b400",
                    "gasPrice": "0x0a",
                    "nonce": "0x00",
                    "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
                    "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                    "to": "0xcccccccccccccccccccccccccccccccccccccccc",
                    "value": "0x01"
                },
                {
                    "hash": "0x1a3420dfb2280397c1b81ff159bd4d6eddc12d7e333e82a01fd4afafad3b2ae4",
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "data": "0x693c61390000000000000000000000000000000000000000000000000000000000000001",
                    "gasLimit": "0x04c4b400",
                    "gasPrice": "0x0a",
                    "nonce": "0x00",
                    "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
                    "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                    "to": "0xcccccccccccccccccccccccccccccccccccccccc",
                    "value": "0x01"
                },
                {
                    "hash": "0x416be8cb4f40d5a29ed56578cf776c5198e58c181ab3534a1094df5f7f61fb02",
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "data": "0x693c61390000000000000000000000000000000000000000000000000000000000000002",
                    "gasLimit": "0x04c4b400",
                    "gasPrice": "0x0a",
                    "nonce": "0x00",
                    "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
                    "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                    "to": "0xcccccccccccccccccccccccccccccccccccccccc",
                    "value": "0x01"
                },
                {
                    "type": "0x00",
                    "chainId": "0x01",
                    "nonce": "0x00",
                    "gasPrice": "0x0a",
                    "gasLimit": "0x07a120",
                    "to": "0x0000000000000000000000000000000000001000",
                    "value": "0x00",
                    "data": "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                    "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
                },
                {
                    "type": "0x00",
                    "chainId": "0x01",
                    "nonce": "0x00",
                    "gasPrice": "0x0a",
                    "gasLimit": "0x0f4240",
                    "to": "0x0000000000000000000000000000000000001001",
                    "value": "0x00",
                    "data": "0x",
                    "sender": "0x8a0a19589531694250d570040a0c4b74576919b8"
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
                "balance": "0x3635c9adc5dea00000",
                "code": "0x",
                "nonce": "0x00",
                "storage": {}
            },
            "0xcccccccccccccccccccccccccccccccccccccccc": {
                "balance": "0x0ba1a9ce0ba1a9ce",
                "code": "0x600060006000600060006004356101000162fffffff100",
                "nonce": "0x00",
                "storage": {}
            },
            "0x0000000000000000000000000000000000001000": {
                "nonce": "0x01",
                "balance": "0x00",
                "code": "0x36600060003760006000366000600060055af16000557f601038036010600039601038036000f3000000000000000000000000000000006000523d600060103e3d60100160006000f000",
                "storage": {}
            },
            "0x0000000000000000000000000000000000001001": {
                "nonce": "0x01",
                "balance": "0x00",
                "code": "0x60006000525a6000600060206000600060085af1505a90035a6000600060206000600073a94f5374fce5edbc8e2a8697c15331677e6ebf0b5af1505a900390031560005500",
                "storage": {
                    "0x00": "0xdeadbeef"
                }
            },
            "0x8a0a19589531694250d570040a0c4b74576919b8": {
                "nonce": "0x00",
                "balance": "0x3635c9adc5dea00000",
                "code": "0x",
                "storage": {}
            }
        }
    }
}
)json";
        auto state_transition = StateTransition(json_str, false, true);
        auto total_gas = state_transition.run();
        std::cout << "Total Gas: " << total_gas;

    } catch (const std::exception& e) {
        // code to handle exceptions of type std::exception and its derived classes
        const auto desc = e.what();
        std::cerr << "Exception: " << desc << std::endl;
    } catch (...) {
        // code to handle any other type of exception
        std::cerr << "An unknown exception occurred" << std::endl;
    }
}
