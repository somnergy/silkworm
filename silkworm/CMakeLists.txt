# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# project(silkworm LANGUAGES CXX)


# Silkworm itself
add_subdirectory(core)
add_subdirectory(dev)

if(SILKWORM_WASM_API)
  add_subdirectory(wasm)
endif()
