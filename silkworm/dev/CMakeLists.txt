# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(nlohmann_json REQUIRED)

set(LIBS_PRIVATE 
)

# cmake-format: off
set(LIBS_PUBLIC
    ethash::keccak
    nlohmann_json::nlohmann_json
    silkworm_core
)
# cmake-format: on

silkworm_library(
  silkworm_dev
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

## Enable it only for local testing due to gmp ld linking issue
# add_subdirectory(cli)
